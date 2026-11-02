package parser

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/mrlyc/llm-tracer/internal/model"
)

var targetQuestionMap = map[string]string{
	"CLICK":     "click_target",
	"TYPE_TEXT": "type_text_target",
	"SELECT":    "select_target",
	"DONE":      "done_target",
}

// ParseSystemOne parses a TypeSafe JEV /systemone request and response.
func ParseSystemOne(reqBody []byte, respBody []byte) (*model.SystemOneStepSummary, error) {
	summary := &model.SystemOneStepSummary{}
	var req map[string]any
	if len(reqBody) > 0 {
		if err := json.Unmarshal(reqBody, &req); err != nil {
			return summary, fmt.Errorf("unmarshal systemone request: %w", err)
		}
	}
	summary.Model = asString(req["model"])

	// Extract state
	elementsByIdx := map[string]string{}
	if state, ok := req["state"].(map[string]any); ok {
		if page, ok := state["page"].(map[string]any); ok {
			summary.Page.URL = asString(page["url"])
			summary.Page.Title = asString(page["title"])
			fullText := asString(page["text"])
			summary.Page.TextLen = len(fullText)
			summary.Page.TextSnippet = truncateString(fullText, 400)
		}
		if elems, ok := state["elements"].([]any); ok {
			summary.Page.ElementCount = len(elems)
			for _, rawEl := range elems {
				if elMap, ok := rawEl.(map[string]any); ok {
					idx := asString(elMap["index"])
					lbl := asString(elMap["label"])
					if idx != "" {
						elementsByIdx[idx] = lbl
					}
				}
			}
		}
		if recent, ok := state["recent_actions"].([]any); ok {
			summary.RecentActionCount = len(recent)
			for _, item := range recent {
				if m, ok := item.(map[string]any); ok {
					summary.RecentActions = append(summary.RecentActions, m)
				}
			}
		}
	}

	// Extract answers from response first so we can merge them into questions
	answersMap := map[string]map[string]any{}
	var resp map[string]any
	if len(respBody) > 0 && json.Unmarshal(respBody, &resp) == nil {
		if respModel := asString(resp["model"]); respModel != "" && summary.Model == "" {
			summary.Model = respModel
		}
		if ansObj, ok := resp["answers"].(map[string]any); ok {
			for qid, rawAns := range ansObj {
				if am, ok := rawAns.(map[string]any); ok {
					answersMap[qid] = am
				}
			}
		}
	}

	// Extract questions in deterministic order (operation first, then targets, then text/others)
	if qMap, ok := req["questions"].(map[string]any); ok {
		qKeys := make([]string, 0, len(qMap))
		for k := range qMap {
			qKeys = append(qKeys, k)
		}
		sort.Slice(qKeys, func(i, j int) bool {
			ri, rj := questionRank(qKeys[i]), questionRank(qKeys[j])
			if ri != rj {
				return ri < rj
			}
			return qKeys[i] < qKeys[j]
		})

		for _, qid := range qKeys {
			rawQ, ok := qMap[qid].(map[string]any)
			if !ok {
				continue
			}
			qItem := model.SystemOneQuestion{
				ID:      qid,
				Type:    asString(rawQ["type"]),
				Options: make(map[string]string),
				Probs:   make(map[string]float64),
			}
			if instr, ok := rawQ["instructions"].(map[string]any); ok {
				qItem.Goal = asString(instr["goal"])
				if summary.Goal == "" && qItem.Goal != "" {
					summary.Goal = qItem.Goal
				}
				qItem.Operation = asString(instr["operation"])
				if guides, ok := instr["guide"].([]any); ok {
					for _, g := range guides {
						if gs := asString(g); gs != "" {
							qItem.Guides = append(qItem.Guides, gs)
						}
					}
				}
			}
			switch crit := rawQ["criteria"].(type) {
			case map[string]any:
				keys := make([]string, 0, len(crit))
				for k := range crit {
					keys = append(keys, k)
				}
				sort.Strings(keys)
				qItem.OptionOrder = keys
				for _, k := range keys {
					v := crit[k]
					switch vm := v.(type) {
					case string:
						qItem.Options[k] = vm
					case map[string]any:
						elDesc := asString(vm["element"])
						if href := asString(vm["href"]); href != "" {
							elDesc += " (" + href + ")"
						}
						qItem.Options[k] = elDesc
					default:
						b, _ := json.Marshal(v)
						qItem.Options[k] = string(b)
					}
				}
			case []any:
				for _, item := range crit {
					s := asString(item)
					qItem.OptionOrder = append(qItem.OptionOrder, s)
					qItem.Options[s] = s
				}
			}

			if ans, ok := answersMap[qid]; ok {
				if ch, ok := ans["choice"].(string); ok {
					qItem.AnswerChoice = ch
					qItem.TopChoice = ch
				}
				if conf, ok := asFloat(ans["confidence"]); ok {
					qItem.Confidence = conf
				}
				if probs, ok := ans["probabilities"].(map[string]any); ok {
					bestKey := ""
					bestProb := -1.0
					for pk, pv := range probs {
						if pf, ok := asFloat(pv); ok {
							qItem.Probs[pk] = pf
							if pf > bestProb {
								bestProb = pf
								bestKey = pk
							}
						}
					}
					if qItem.AnswerChoice != "" {
						qItem.TopChoice = qItem.AnswerChoice
					} else if bestKey != "" {
						qItem.TopChoice = bestKey
						qItem.UsedArgmax = true
					}
				}
			}
			summary.Questions = append(summary.Questions, qItem)
		}
	}

	// Populate high-level step decision summary
	qByID := make(map[string]model.SystemOneQuestion, len(summary.Questions))
	for _, q := range summary.Questions {
		qByID[q.ID] = q
	}
	var fallbacks []string
	if opQ, ok := qByID["operation"]; ok && opQ.TopChoice != "" {
		summary.SelectedOp = opQ.TopChoice
		summary.OpConfidence = opQ.Confidence
		summary.QuestionsUsed = append(summary.QuestionsUsed, "operation")
		if opQ.UsedArgmax {
			fallbacks = append(fallbacks, fmt.Sprintf("operation choice was null; used argmax %s", opQ.TopChoice))
		}
		if targetQID, hasTarget := targetQuestionMap[summary.SelectedOp]; hasTarget {
			if tq, ok := qByID[targetQID]; ok && tq.TopChoice != "" {
				summary.SelectedTarget = tq.TopChoice
				summary.TargetConfidence = tq.Confidence
				summary.QuestionsUsed = append(summary.QuestionsUsed, targetQID)
				if desc, ok := tq.Options[tq.TopChoice]; ok && desc != "" {
					summary.SelectedElement = desc
				} else {
					baseIdx := strings.Split(tq.TopChoice, ":")[0]
					if lbl, ok := elementsByIdx[baseIdx]; ok {
						summary.SelectedElement = fmt.Sprintf("[%s] %s", baseIdx, lbl)
					}
				}
				if tq.UsedArgmax {
					fallbacks = append(fallbacks, fmt.Sprintf("%s choice was null; used argmax %s", targetQID, tq.TopChoice))
				}
			}
		}
		if summary.SelectedOp == "TYPE_TEXT" {
			if textQ, ok := qByID["text"]; ok && textQ.TopChoice != "" {
				summary.SelectedText = textQ.TopChoice
				summary.QuestionsUsed = append(summary.QuestionsUsed, "text")
				if textQ.UsedArgmax {
					fallbacks = append(fallbacks, fmt.Sprintf("text choice was null; used argmax %q", textQ.TopChoice))
				}
			}
		}
	}
	if len(fallbacks) > 0 {
		summary.FallbackReason = strings.Join(fallbacks, "; ")
	}
	return summary, nil
}

func questionRank(qid string) int {
	switch qid {
	case "operation":
		return 0
	case "click_target":
		return 1
	case "type_text_target":
		return 2
	case "select_target":
		return 3
	case "done_target":
		return 4
	case "text":
		return 5
	default:
		return 10
	}
}
