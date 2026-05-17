package main

// 定义低 20 位的掩码用于应用识别 0x100/0x000FFFFF

// LoadRules 返回域名与 Mark 的映射关系
// 后续可以改为从 yaml 或 json 配置文件读取
func LoadRules() map[string]uint32 {
	return map[string]uint32{
		"google.com": 100,
		"github.com": 200,
		"baidu.com":  300,
		"shifen.com": 300,
	}
}
