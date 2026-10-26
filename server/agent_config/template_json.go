/*
 * Copyright (c) 2024 Yunshan Networks
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package agent_config

import (
	jsoniter "github.com/json-iterator/go"

	"fmt"
	"math"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

var json = jsoniter.ConfigCompatibleWithStandardLibrary

const (
	keyCommentSuffix = "_comment"
	dictValueComment = "value_comments"

	commentFlag          = "#"
	dictValueCommentFlag = "# ---" // 字典值里每个字段的注释标记
	todoFlag             = "TODO"

	templateIndent = "  "
)

func ConvertYAMLToJSON(yamlData []byte) ([]byte, error) {
	keyToComment, err := NewTemplateFormatter(YamlAgentGroupConfigTemplate).GenerateKeyToComment()
	if err != nil {
		return nil, fmt.Errorf("generate key to comment error: %v", err)
	}
	dataFmt := NewDataFormatter()
	err = dataFmt.LoadYAMLData(yamlData)
	if err != nil {
		return nil, fmt.Errorf("new data formatter error: %v", err)
	}
	return dataFmt.mapToJSON(keyToComment)
}

func BatchConvertYAMLToJSON(yamlDatas [][]byte) ([][]byte, error) {
	if len(yamlDatas) == 0 {
		return [][]byte{}, nil
	}
	keyToComment, err := NewTemplateFormatter(YamlAgentGroupConfigTemplate).GenerateKeyToComment()
	if err != nil {
		return [][]byte{}, fmt.Errorf("generate key to comment error: %v", err)
	}
	jsonDatas := make([][]byte, 0, len(yamlDatas))
	for _, yamlData := range yamlDatas {
		if len(yamlData) == 0 {
			jsonDatas = append(jsonDatas, []byte("{}"))
			continue
		}
		dataFmt := NewDataFormatter()
		err = dataFmt.LoadYAMLData(yamlData)
		if err != nil {
			return [][]byte{}, fmt.Errorf("load yaml data error: %v", err)
		}
		jsonData, err := dataFmt.mapToJSON(keyToComment)
		if err != nil {
			return [][]byte{}, fmt.Errorf("map to json error: %v", err)
		}
		jsonDatas = append(jsonDatas, jsonData)
	}
	return jsonDatas, nil
}

func ValidateYAML(yamlData []byte) error {
	tmplFmt := NewTemplateFormatter(YamlAgentGroupConfigTemplate)
	KeyToComment, err := tmplFmt.GenerateKeyToComment()
	if err != nil {
		return fmt.Errorf("generate key to comment error: %v", err)
	}
	tmplFmt.DataFormatter.fmtMapValAndRefresh(KeyToComment, true)

	dataFmt := NewDataFormatter()
	err = dataFmt.LoadYAMLData(yamlData)
	if err != nil {
		return fmt.Errorf("new data formatter error: %v", err)
	}
	if err := dataFmt.validateYAMLDictValues("", dataFmt.mapData, KeyToComment); err != nil {
		return err
	}
	err = dataFmt.fmtMapValAndRefresh(KeyToComment, true)
	if err != nil {
		return fmt.Errorf("convert value and refresh error: %v", err)
	}

	return validateNodeAgainstTemplate(dataFmt.yamlNode, tmplFmt.DataFormatter.yamlNode)
}

func ConvertJSONToYAMLAndValidate(jsonData map[string]interface{}) ([]byte, error) {
	tmplFmt := NewTemplateFormatter(YamlAgentGroupConfigTemplate)
	KeyToComment, err := tmplFmt.GenerateKeyToComment()
	if err != nil {
		return nil, fmt.Errorf("generate key to comment error: %v", err)
	}
	tmplFmt.DataFormatter.fmtMapValAndRefresh(KeyToComment, true)

	dataFmt := NewDataFormatter()
	dataFmt.setKeyToComment(KeyToComment)
	err = dataFmt.LoadMapData(jsonData)
	if err != nil {
		return nil, fmt.Errorf("new data formatter error: %v", err)
	}
	err = dataFmt.fmtMapValAndRefresh(KeyToComment, true)
	if err != nil {
		return nil, fmt.Errorf("convert value and refresh error: %v", err)
	}

	if err := validateNodeAgainstTemplate(dataFmt.yamlNode, tmplFmt.DataFormatter.yamlNode); err != nil {
		return nil, err
	}

	return dataFmt.formattedYAMLData, nil
}

func validateNodeAgainstTemplate(node, nodeTemplate *yaml.Node) error {
	if node.Kind != nodeTemplate.Kind {
		return fmt.Errorf("node kind mismatch: expected %v, got %v", nodeTemplate.Kind, node.Kind)
	}

	switch node.Kind {
	case yaml.DocumentNode:
		if len(node.Content) != len(nodeTemplate.Content) {
			return fmt.Errorf("document node content length mismatch")
		}
		for i := range node.Content {
			if err := validateNodeAgainstTemplate(node.Content[i], nodeTemplate.Content[i]); err != nil {
				return err
			}
		}
	case yaml.MappingNode:
		nodeMap := make(map[string]*yaml.Node)
		for i := 0; i < len(node.Content); i += 2 {
			nodeMap[node.Content[i].Value] = node.Content[i+1]
		}

		templateMap := make(map[string]*yaml.Node)
		for i := 0; i < len(nodeTemplate.Content); i += 2 {
			templateMap[nodeTemplate.Content[i].Value] = nodeTemplate.Content[i+1]
		}

		for key, value := range nodeMap {
			if templateValue, exists := templateMap[key]; exists {
				if err := validateNodeAgainstTemplate(value, templateValue); err != nil {
					return fmt.Errorf("invalid value for key '%s': %v", key, err)
				}
			} else {
				return fmt.Errorf("unexpected key in configuration: %s", key)
			}
		}
	case yaml.SequenceNode:
		if len(node.Content) > 0 && len(nodeTemplate.Content) > 0 {
			for _, item := range node.Content {
				if err := validateNodeAgainstTemplate(item, nodeTemplate.Content[0]); err != nil {
					return fmt.Errorf("invalid sequence item: %v", err)
				}
			}
		}
		// TODO validate sequence content by comment
	case yaml.ScalarNode:
		if nodeTemplate.Tag == "!!null" { // TODO more strict validation
			return nil
		}
		if nodeTemplate.Tag == "!!float" && node.Tag == "!!int" {
			return nil
		}
		if node.Tag != nodeTemplate.Tag {
			return fmt.Errorf("scalar type mismatch: expected %s, got %s", nodeTemplate.Tag, node.Tag)
		}
	case yaml.AliasNode:
		if nodeTemplate.Kind != yaml.AliasNode {
			return fmt.Errorf("unexpected alias node")
		}
		// For alias nodes, we should validate the actual content they refer to
		if err := validateNodeAgainstTemplate(node.Alias, nodeTemplate.Alias); err != nil {
			return fmt.Errorf("invalid alias node: %v", err)
		}
	default:
		return fmt.Errorf("unsupported node kind: %v", node.Kind)
	}

	return nil
}

func ConvertTemplateYAMLToJSON(d DynamicOptions) ([]byte, error) {
	return NewTemplateFormatter(YamlAgentGroupConfigTemplate).mapToJSON(d)
}

type KeyToComment map[string]map[string]interface{}

type TemplateFormatter struct {
	lineFmt *LineFormatter
	DataFormatter
}

func NewTemplateFormatter(data []byte) *TemplateFormatter {
	return &TemplateFormatter{
		lineFmt: NewLineFormatter(data),
	}
}

func (f *TemplateFormatter) mapToJSON(d DynamicOptions) ([]byte, error) {
	formattedLines, err := f.lineFmt.Format()
	if err != nil {
		return nil, fmt.Errorf("format template yaml lines error: %v", err)
	}

	err = f.DataFormatter.LoadYAMLData(formattedLines)
	if err != nil {
		return nil, fmt.Errorf("LoadYAMLData data formatter error: %v", err)
	}
	keyToComment := make(KeyToComment)
	if err := f.generateKeyComment(f.mapData, "", keyToComment); err != nil {
		return nil, err
	}
	err = f.DataFormatter.fmtMapValAndRefresh(keyToComment, true)
	if err != nil {
		return nil, fmt.Errorf("convert dict value to string error: %v", err)
	}

	formattedNode, err := f.fillingEnumOptions(f.DataFormatter.yamlNode, "", d)
	if err != nil {
		return nil, fmt.Errorf("filling enum options error: %v", err)
	}
	formattedMap, err := f.fillingOrder(formattedNode)
	if err != nil {
		return nil, fmt.Errorf("filling order error: %v", err)
	}
	return f.formatJson(formattedMap)
}

func (f *TemplateFormatter) fillingEnumOptions(node *yaml.Node, ancestors string, d DynamicOptions) (*yaml.Node, error) {
	switch node.Kind {
	case yaml.DocumentNode:
		return f.fillingEnumOptions(node.Content[0], ancestors, d)
	case yaml.MappingNode:
		for i := 0; i < len(node.Content); i += 2 {
			newAncestors := node.Content[i].Value
			if ancestors != "" {
				newAncestors = ancestors + "." + newAncestors
			}
			value, err := f.fillingEnumOptions(node.Content[i+1], newAncestors, d)
			if err != nil {
				return nil, err
			}
			node.Content[i+1] = value
		}
		return node, nil
	case yaml.SequenceNode:
		value := make([]*yaml.Node, 0)
		if dynamicValue, ok := d[ancestors]; ok {
			for _, contentNode := range node.Content {
				if contentNode.Kind == yaml.MappingNode {
					for i := 0; i < len(contentNode.Content); i += 2 {
						key := contentNode.Content[i].Value
						if key != "_DYNAMIC_OPTIONS_" {
							value = append(value, contentNode)
						}
					}
				}
			}
			value = append(value, dynamicValue.Content...)
		} else {
			for _, contentNode := range node.Content {
				valueNode, err := f.fillingEnumOptions(contentNode, ancestors, d)
				if err != nil {
					return nil, err
				}
				value = append(value, valueNode)
			}
		}
		node.Content = value
		return node, nil
	case yaml.ScalarNode:
		return node, nil
	default:
		return nil, fmt.Errorf("unsupported YAML node kind: %v", node.Kind)
	}
}

func (f *TemplateFormatter) fillingOrder(node *yaml.Node) (interface{}, error) {
	switch node.Kind {
	case yaml.DocumentNode:
		return f.fillingOrder(node.Content[0])
	case yaml.MappingNode:
		values := make(map[string]interface{})
		for i := 0; i < len(node.Content); i += 2 {
			keyNode := node.Content[i]
			valueNode := node.Content[i+1]

			key := keyNode.Value
			value, err := f.fillingOrder(valueNode)
			if err != nil {
				return nil, err
			}

			if strings.HasSuffix(key, keyCommentSuffix) {
				if valueMap, ok := value.(map[string]interface{}); ok {
					valueMap["order"] = i/2 + 1
					value = valueMap
				}
			}
			values[key] = value
		}
		return values, nil
	case yaml.SequenceNode:
		var seq []interface{}
		for i, contentNode := range node.Content {
			value, err := f.fillingOrder(contentNode)
			if err != nil {
				return nil, err
			}
			if valueMap, ok := value.(map[string]interface{}); ok {
				valueMap["order"] = i + 1
				value = valueMap
			}
			seq = append(seq, value)
		}
		return seq, nil
	case yaml.ScalarNode:
		if node.Tag == "!!int" {
			if intValue, err := strconv.Atoi(node.Value); err == nil {
				return intValue, nil
			}
			intValue, err := strconv.ParseInt(node.Value, 0, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid integer %q: %w", node.Value, err)
			}
			return intValue, nil
		} else if node.Tag == "!!bool" {
			boolValue, err := strconv.ParseBool(node.Value)
			if err != nil {
				return nil, err
			}
			return boolValue, nil
		} else if node.Tag == "!!float" {
			floatValue, err := strconv.ParseFloat(node.Value, 64)
			if err != nil {
				return nil, err
			}
			return floatValue, nil
		}
		return node.Value, nil
	default:
		return nil, fmt.Errorf("unsupported YAML node kind: %v", node.Kind)
	}
}

func (f *TemplateFormatter) GenerateKeyToComment() (KeyToComment, error) {
	formattedLines, err := f.lineFmt.Format()
	if err != nil {
		return nil, fmt.Errorf("format template yaml lines error: %v", err)
	}
	err = f.DataFormatter.LoadYAMLData(formattedLines)
	if err != nil {
		return nil, fmt.Errorf("LoadYAMLData data formatter error: %v", err)
	}

	keyToComment := make(KeyToComment)
	if err := f.generateKeyComment(f.mapData, "", keyToComment); err != nil {
		return nil, err
	}
	return keyToComment, nil
}

func (f *TemplateFormatter) generateKeyComment(data interface{}, ancestors string, result KeyToComment) error {
	mapping, ok := data.(map[string]interface{})
	if !ok {
		return nil
	}
	for key, value := range mapping {
		newAncestors := f.appendAncestor(ancestors, key)
		if f.isKeyComment(key) {
			comment, ok := value.(map[string]interface{})
			if !ok {
				return fmt.Errorf("metadata for %s must be a mapping", newAncestors)
			}
			result[newAncestors] = comment
		}
		if err := f.generateKeyComment(value, newAncestors, result); err != nil {
			return err
		}
	}
	return nil
}

// LineFormatter 将 template.yaml 文件中的注释转换为 yaml section。
// 文件中的多行注释每一行以 # 开头，是多行注释结束后数据字段 key 的说明：
// 1. 添加与数据字段 key 同缩进的说明字段 key_comment。
// 2. 将说明反注释后增加缩进，作为说明字段的值。
//
// 例如：
//
//	# type: section
//	# name:
//	#   en: Global
//	#   ch: 全局配置
//	# description:
//	global:
//
// 其中，# type: section 及至 # description: 行是 section 的说明，global 是 section 的 key，转换后的 yaml 为：
//
//	global_comment:
//	  type: section
//	  name:
//	    en: Global
//	    ch: 全局配置
//	  description:
//	global:
type LineFormatter struct {
	lines []string
}

func NewLineFormatter(bytes []byte) *LineFormatter {
	return &LineFormatter{
		lines: strings.Split(string(bytes), "\n"),
	}
}

func (f *LineFormatter) Format() ([]byte, error) {
	strippedLines := make([]string, 0)
	for i := 0; i < len(f.lines); i++ {
		if f.isCommentLine(f.lines[i]) {
			end, lines, err := f.convCommentToSection(i)
			if err != nil {
				return []byte{}, err
			}
			strippedLines = append(strippedLines, lines...)
			i = end
			continue
		}
		strippedLines = append(strippedLines, f.lines[i])
	}
	return []byte(strings.Join(strippedLines, "\n")), nil
}

func (f *LineFormatter) convCommentToSection(start int) (end int, commentLines []string, err error) {
	if start < 0 || start >= len(f.lines) {
		return 0, nil, fmt.Errorf("comment start is out of range: %d", start)
	}
	i := start
	for ; i < len(f.lines); i++ {
		if !f.isCommentLine(f.lines[i]) {
			break
		}
		if f.isTodoCommentLine(f.lines[i]) {
			i = f.ignoreTodoComments(i)
			continue
		}
		if f.isDictValueCommentLine(f.lines[i]) {
			i, commentLines, err = f.appendDictValueComments(i, commentLines)
			if err != nil {
				return 0, nil, err
			}
			continue
		}
		f.replaceTemplateSyntax(i)
		commentLines = append(commentLines, f.indentLine(f.uncommentLine(f.lines[i]), 1))
	}

	if i >= len(f.lines) {
		return 0, nil, fmt.Errorf("comment at line %d has no following key", start+1)
	}
	keyCommentLine, err := f.keyLineToKeyCommentLine(f.lines[i])
	if err != nil {
		return 0, nil, fmt.Errorf("%w at line: %d", err, i+1)
	}
	return i - 1, append([]string{keyCommentLine}, commentLines...), nil
}

func (f *LineFormatter) indentLine(line string, indentCount int) string {
	for i := 0; i < indentCount; i++ {
		line = templateIndent + line
	}
	return line
}

func (f *LineFormatter) uncommentLine(line string) string {
	line = strings.Replace(line, commentFlag+" ", "", 1)
	if f.isStandaloneCommentLine(line) {
		line = strings.Replace(line, commentFlag, "", 1)
	}
	return line
}

func (f *LineFormatter) isCommentLine(line string) bool {
	return strings.HasPrefix(strings.TrimSpace(line), commentFlag)
}

func (f *LineFormatter) isStandaloneCommentLine(line string) bool {
	return f.isCommentLine(line) && strings.TrimSpace(line) == commentFlag
}

func (f *LineFormatter) isDictValueCommentLine(line string) bool {
	return strings.HasPrefix(strings.TrimSpace(line), dictValueCommentFlag)
}

func (f *LineFormatter) isTodoCommentLine(line string) bool {
	return (f.isCommentLine(line) && strings.Contains(line, todoFlag))
}

func (f *LineFormatter) keyLineToKeyCommentLine(line string) (string, error) {
	parts := strings.SplitN(line, ":", 2)
	if len(parts) != 2 {
		return "", fmt.Errorf("failed to split key line: %s by \":\"", line)
	}
	key := parts[0]
	keyCommentLine := key + keyCommentSuffix + ":"
	return keyCommentLine, nil
}

func (f *LineFormatter) ignoreDictValueComments(start int) (end int) {
	j := start + 1
	for ; j < len(f.lines); j++ {
		if !f.isCommentLine(f.lines[j]) {
			break
		}
	}
	return j - 1
}

func (f *LineFormatter) appendDictValueComments(start int, result []string) (end int, appendedResult []string, err error) {
	indentCount := 1
	basePrefix := strings.SplitN(f.lines[start], commentFlag, 2)[0]
	result = append(result, f.indentLine(basePrefix+dictValueComment+":", indentCount))
	end, result, err = f.convDictValueCommentToSection(start, indentCount+1, result)
	return end, result, err
}

func (f *LineFormatter) convDictValueCommentToSection(start int, yamlIndentCount int, result []string) (end int, appendedResult []string, err error) {
	if start < 0 || start >= len(f.lines) {
		return 0, nil, fmt.Errorf("dict metadata at line %d has no following key", start+1)
	}
	if !f.isCommentLine(f.lines[start]) {
		return start - 1, result, nil
	}
	if !f.isDictValueCommentLine(f.lines[start]) {
		return 0, nil, fmt.Errorf("expected dict metadata separator at line %d", start+1)
	}
	commentLines := make([]string, 0)
	i := start + 1
	for ; i < len(f.lines); i++ {
		if !f.isCommentLine(f.lines[i]) {
			if len(commentLines) == 0 {
				// Preserve empty/TODO-only legacy schema separators.
				return i - 1, result, nil
			}
			return 0, nil, fmt.Errorf("dict metadata at line %d has no default document", start+1)
		}
		if f.isDictValueCommentLine(f.lines[i]) {
			break
		}
		if f.isTodoCommentLine(f.lines[i]) {
			i = f.ignoreTodoComments(i)
			continue
		}
		commentLines = append(commentLines, f.indentLine(f.uncommentLine(f.lines[i]), yamlIndentCount+1))
	}
	fieldLine := i + 1
	if fieldLine >= len(f.lines) || !f.isCommentLine(f.lines[fieldLine]) || f.isDictValueCommentLine(f.lines[fieldLine]) {
		return 0, nil, fmt.Errorf("dict metadata at line %d has no default field", start+1)
	}
	fieldName := f.indentLine(f.uncommentLine(f.lines[fieldLine]), yamlIndentCount)
	fieldNameComment, err := f.keyLineToKeyCommentLine(fieldName)
	if err != nil {
		return 0, nil, fmt.Errorf("%w at line: %d", err, fieldLine+1)
	}
	result = append(result, append([]string{fieldName, fieldNameComment}, commentLines...)...)
	return f.convDictValueCommentToSection(fieldLine+1, yamlIndentCount, result)
}

func (f *LineFormatter) ignoreTodoComments(start int) (end int) {
	j := start + 1
	for ; j < len(f.lines); j++ {
		if !f.isTodoCommentLine(f.lines[j]) {
			break
		}
	}
	return j - 1
}

func (f *LineFormatter) replaceTemplateSyntax(i int) {
	if YamlSubTemplateRegex.MatchString(f.lines[i]) {
		sublines := strings.Split(YamlSubTemplateRegex.ReplaceAllStringFunc(f.lines[i], ReplaceTemplateSyntax(true)), "\n")
		sublinesBuilder := strings.Builder{}
		for _, line := range sublines {
			sublinesBuilder.WriteString("\n")
			sublinesBuilder.WriteString(f.indentLine(f.uncommentLine(line), 1))
		}
		f.lines[i] = sublinesBuilder.String()
	}
}

type DynamicOptions map[string]*yaml.Node

type DataFormatter struct {
	// Only decoded JSON numbers may be normalized to integer schema fields.
	jsonInput    bool
	keyToComment KeyToComment

	formattedYAMLData []byte // 与 template.yaml 文件格式一致的 yaml 数据
	mapData           map[string]interface{}
	yamlNode          *yaml.Node
}

func NewDataFormatter() *DataFormatter {
	return &DataFormatter{}
}

func (f *DataFormatter) setKeyToComment(keyToComment KeyToComment) {
	f.keyToComment = keyToComment
}

func (f *DataFormatter) LoadMapData(data map[string]interface{}) error {
	f.jsonInput = true
	converted, err := f.prepareJSONNumbers(data, "")
	if err != nil {
		return err
	}
	f.mapData = converted.(map[string]interface{})
	yamlData, err := f.mapToYAML()
	if err != nil {
		return fmt.Errorf("convert json to yaml error: %v", err)
	}

	var yamlNode yaml.Node
	err = yaml.Unmarshal(yamlData, &yamlNode)
	if err != nil {
		return fmt.Errorf("unmarshal yaml to node error: %v", err)
	}

	err = f.fmtVal("", f.mapData, f.keyToComment, false)
	if err != nil {
		return fmt.Errorf("convert dict value to string error: %v", err)
	}
	f.formattedYAMLData, err = f.mapToYAML()
	if err != nil {
		return fmt.Errorf("convert json to yaml error: %v", err)
	}

	return nil
}

func (f *DataFormatter) mapToYAML() ([]byte, error) {
	str, err := f.dictToString(f.mapData)
	if err != nil {
		return nil, fmt.Errorf("convert dict to string error: %v", err)
	}
	return []byte(str), nil
}

func (f *DataFormatter) LoadYAMLData(yamlData []byte) error {
	f.jsonInput = false
	var mapData map[string]interface{}
	err := yaml.Unmarshal(yamlData, &mapData)
	if err != nil {
		return fmt.Errorf("unmarshal data to map error: %v", err)
	}
	var yamlNode yaml.Node
	err = yaml.Unmarshal(yamlData, &yamlNode)
	if err != nil {
		return fmt.Errorf("unmarshal data to yaml node error: %v", err)
	}
	f.mapData = mapData
	f.yamlNode = &yamlNode
	return nil
}

func (f *DataFormatter) mapToJSON(keyToComment KeyToComment) ([]byte, error) {
	err := f.fmtMapValAndRefresh(keyToComment, true)
	if err != nil {
		return nil, fmt.Errorf("convert value and refresh error: %v", err)
	}
	bytes, err := f.formatJson(f.mapData)
	if err != nil {
		return nil, fmt.Errorf("format json error: %v", err)
	}
	return bytes, nil
}

func (f *DataFormatter) fmtMapValAndRefresh(keyToComment KeyToComment, dictValToStr bool) error {
	err := f.fmtVal("", f.mapData, keyToComment, dictValToStr)
	if err != nil {
		return fmt.Errorf("convert dict value to string error: %v", err)
	}
	// refresh yamlNode if changes dict value
	if _, ok := keyToComment["valueChanged"]; ok {
		yamlBytes, err := yaml.Marshal(f.mapData)
		if err != nil {
			return fmt.Errorf("marshal map to yaml error: %v", err)
		}
		var yamlNode yaml.Node
		err = yaml.Unmarshal(yamlBytes, &yamlNode)
		if err != nil {
			return fmt.Errorf("unmarshal yaml to node error: %v", err)
		}
		preserveYAMLFloatTags(&yamlNode, f.yamlNode)
		f.yamlNode = &yamlNode
	}
	return nil
}

// Native Agent YAML requires actual collections; GUI JSON may carry YAML text.
func (f *DataFormatter) validateYAMLDictValues(ancestor string, data interface{}, comments KeyToComment) error {
	mapping, ok := data.(map[string]interface{})
	if !ok {
		return nil
	}
	for key, value := range mapping {
		path := f.appendAncestor(ancestor, key)
		if f.isDictValue(comments[path]) {
			switch value.(type) {
			case map[string]interface{}, []interface{}, nil:
			default:
				return fmt.Errorf("YAML dict must be a mapping or sequence, key: %s", path)
			}
			continue
		}
		if err := f.validateYAMLDictValues(path, value, comments); err != nil {
			return err
		}
	}
	return nil
}

func (f *DataFormatter) fmtVal(ancestors string, data interface{}, keyToComment KeyToComment, dictValToStr bool) error {
	switch data := data.(type) {
	case map[string]interface{}:
		for key, value := range data {
			if f.isKeyComment(key) {
				continue
			}
			newAncestors := f.appendAncestor(ancestors, key)
			if f.isDictValue(keyToComment[newAncestors]) {
				if dictValToStr {
					valueStr, err := f.dictToString(value)
					if err != nil {
						return fmt.Errorf("convert dict value to string error: %v, key: %s", err, newAncestors)
					}
					data[key] = valueStr
				} else {
					switch typed := value.(type) {
					case string:
						var converted interface{}
						if err := yaml.Unmarshal([]byte(typed), &converted); err != nil {
							return fmt.Errorf("unmarshal dict value: %w, key: %s", err, newAncestors)
						}
						switch converted.(type) {
						case map[string]interface{}, []interface{}, nil:
							data[key] = converted
						default:
							return fmt.Errorf("dict value must be a mapping or sequence, key: %s", newAncestors)
						}
					case map[string]interface{}, []interface{}, nil:
						// LoadMapData and validation may normalize the same value twice.
					default:
						return fmt.Errorf("dict value must be YAML text, mapping or sequence, key: %s", newAncestors)
					}
				}
				keyToComment["valueChanged"] = make(map[string]interface{})
			} else if f.isIntValue(keyToComment[newAncestors]) {
				switch value := value.(type) {
				case int:
					data[key] = value
				case float64:
					if !f.jsonInput {
						return fmt.Errorf("YAML float is invalid for integer field, key: %s", newAncestors)
					}
					if f.jsonInput {
						upper := math.Ldexp(1, strconv.IntSize-1)
						if math.IsNaN(value) || math.IsInf(value, 0) || math.Trunc(value) != value || value < -upper || value >= upper {
							return fmt.Errorf("JSON integer is inexact or out of range, key: %s", newAncestors)
						}
						data[key] = int(value)
						keyToComment["valueChanged"] = make(map[string]interface{})
					}
				}
			}
			if err := f.fmtVal(newAncestors, data[key], keyToComment, dictValToStr); err != nil {
				return err
			}
		}
	case []interface{}:
		// Sequences inherit the field metadata. YAML decoding has already resolved
		// aliases and merge keys, so numeric types must be checked before re-encode.
		for _, item := range data {
			if err := f.fmtVal(ancestors, item, keyToComment, dictValToStr); err != nil {
				return err
			}
		}
	case float64:
		if !f.jsonInput && f.isIntValue(keyToComment[ancestors]) {
			return fmt.Errorf("YAML float is invalid for integer field, key: %s", ancestors)
		}
	default:
		return nil
	}
	return nil
}

// Normalize actual map values rather than editing serialized JSON text: a
// description or user value can legitimately contain the substring ": null".
func normalizeJSONMapValues(data interface{}, mapValue bool) interface{} {
	switch value := data.(type) {
	case map[string]interface{}:
		if value == nil {
			if mapValue {
				return []interface{}{}
			}
			return nil
		}
		result := make(map[string]interface{}, len(value))
		for key, child := range value {
			result[key] = normalizeJSONMapValues(child, true)
		}
		return result
	case []interface{}:
		if value == nil {
			if mapValue {
				return []interface{}{}
			}
			return nil
		}
		result := make([]interface{}, len(value))
		for i, child := range value {
			result[i] = normalizeJSONMapValues(child, false)
		}
		return result
	case nil:
		if mapValue {
			return []interface{}{}
		}
	case string:
		if mapValue && value == "null" {
			return ""
		}
	}
	return data
}

func (f *DataFormatter) formatJson(data interface{}) ([]byte, error) {
	encoded, err := json.MarshalIndent(normalizeJSONMapValues(data, false), "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal json error: %w", err)
	}
	return encoded, nil
}

func (f *DataFormatter) dictToString(data interface{}) (string, error) {
	if str, ok := data.(string); ok {
		return f.listToString(str)
	}
	switch data.(type) {
	case map[string]interface{}, []interface{}, nil:
	default:
		return "", fmt.Errorf("dict value must be a mapping or sequence")
	}
	var buf strings.Builder
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	err := enc.Encode(data)
	if err != nil {
		return "", err
	}
	return buf.String(), nil
}

func (f *DataFormatter) listToString(data string) (string, error) {
	var collection interface{}
	if err := yaml.Unmarshal([]byte(data), &collection); err != nil {
		return "", fmt.Errorf("unmarshal dict collection: %w", err)
	}
	switch collection.(type) {
	case map[string]interface{}, []interface{}:
	case nil:
		collection = []interface{}{}
	default:
		return "", fmt.Errorf("dict text must contain a mapping or sequence")
	}
	output, err := yaml.Marshal(collection)
	return string(output), err
}

func (f *DataFormatter) isKeyComment(key string) bool {
	return strings.HasSuffix(key, keyCommentSuffix)
}

func (f *DataFormatter) appendAncestor(ancestor, key string) string {
	key = strings.TrimSuffix(key, keyCommentSuffix)
	if ancestor == "" {
		return key
	}
	return ancestor + "." + key
}

func (f *DataFormatter) isDictValue(comment map[string]interface{}) bool {
	if _, ok := comment["type"]; ok {
		return comment["type"] == "dict"
	}
	return false
}

func (f *DataFormatter) isIntValue(comment map[string]interface{}) bool {
	if _, ok := comment["type"]; ok {
		return comment["type"] == "int"
	}
	return false
}

func ReplaceTemplateSyntax(addNewLine bool) func(string) string {
	return func(str string) string {
		subMatchers := YamlSubTemplateRegex.FindStringSubmatch(str)
		if len(subMatchers) < 5 {
			return str
		}
		indent := subMatchers[1]
		replaceType := subMatchers[2]
		subType := subMatchers[4]
		subName := subMatchers[3] + "." + subType
		if replaceType == "file" {
			fileContent, err := YamlEmbeddedSubTemplate.ReadFile(subName)
			if err != nil {
				return str
			}
			lines := strings.Split(string(fileContent), "\n")
			var builder strings.Builder
			if addNewLine {
				builder.WriteString("\n")
			}
			builder.WriteString(indent)
			builder.WriteString("```")
			builder.WriteString(subType)
			for _, line := range lines {
				if addNewLine {
					builder.WriteString("\n")
				}
				builder.WriteString(indent)
				builder.WriteString(line)
			}
			if addNewLine {
				builder.WriteString("\n")
			}
			builder.WriteString(indent)
			builder.WriteString("```")
			return builder.String()
		}
		return str
	}
}
