package main

import (
	"net/http"
)

type endpointDoc struct {
	Method  string `json:"method"`
	Path    string `json:"path"`
	Summary string `json:"summary"`
	Group   string `json:"group"`
	Auth    string `json:"auth"` // public | user | admin
}

var endpointDocs = []endpointDoc{
	{"GET", "/health", "健康检查", "运维", "public"},
	{"GET", "/metrics", "Prometheus 指标", "运维", "public"},
	{"GET", "/api/openapi.json", "OpenAPI 文档", "运维", "public"},
	{"GET", "/api/setup/status", "初始化与注册状态", "账户", "public"},
	{"POST", "/api/setup", "创建第一个管理员", "账户", "public"},
	{"POST", "/api/register", "自助注册只读账号", "账户", "public"},
	{"POST", "/api/login", "登录并获取 JWT", "账户", "public"},
	{"GET", "/api/me", "当前账号资料", "账户", "user"},
	{"POST", "/api/me/password", "修改自己的密码", "账户", "user"},
	{"GET", "/api/users", "账号列表", "账户", "admin"},
	{"POST", "/api/users", "创建账号", "账户", "admin"},
	{"PUT", "/api/users", "更新账号", "账户", "admin"},
	{"DELETE", "/api/users", "删除账号", "账户", "admin"},
	{"GET", "/api/config", "读取回显配置", "回显", "user"},
	{"POST", "/api/config", "更新回显配置", "回显", "admin"},
	{"GET", "/api/logs", "查询请求日志", "日志", "user"},
	{"GET", "/api/stats", "概览计数", "日志", "user"},
	{"GET", "/api/metrics/summary", "按小时/维度聚合", "日志", "user"},
	{"GET", "/api/export/logs.csv", "导出日志 CSV", "日志", "user"},
	{"GET", "/api/export/logs.json", "导出日志 JSON", "日志", "user"},
	{"GET", "/api/audit", "审计日志", "日志", "user"},
	{"GET", "/api/audit/export.csv", "导出审计 CSV", "日志", "user"},
	{"POST", "/api/replay", "重放合成请求", "调试", "admin"},
	{"GET", "/api/datasets", "数据集 Provider 列表", "数据", "user"},
	{"POST", "/api/datasets", "新增数据集 Provider", "数据", "admin"},
	{"DELETE", "/api/datasets", "删除数据集 Provider", "数据", "admin"},
	{"GET", "/api/ipproviders", "IP 查询链", "数据", "user"},
	{"POST", "/api/ipproviders", "新增 IP Provider", "数据", "admin"},
	{"POST", "/api/ipproviders/test", "测试 IP Provider", "数据", "admin"},
	{"GET", "/api/ja4/search", "JA4 指纹搜索", "指纹", "user"},
	{"GET", "/api/ja4/stats", "JA4 库统计", "指纹", "user"},
	{"GET", "/api/apikeys", "API Key 列表", "安全", "admin"},
	{"POST", "/api/apikeys", "创建 API Key（仅返回一次）", "安全", "admin"},
	{"PATCH", "/api/apikeys", "启用/停用 API Key", "安全", "admin"},
	{"DELETE", "/api/apikeys", "删除 API Key", "安全", "admin"},
	{"GET", "/api/webhooks", "Webhook 列表", "集成", "admin"},
	{"POST", "/api/webhooks", "创建 Webhook", "集成", "admin"},
	{"PATCH", "/api/webhooks", "启用/停用 Webhook", "集成", "admin"},
	{"DELETE", "/api/webhooks", "删除 Webhook", "集成", "admin"},
	{"POST", "/api/webhooks/test", "发送测试事件", "集成", "admin"},
	{"GET", "/api/notifications", "通知列表", "集成", "user"},
	{"POST", "/api/notifications", "标记已读", "集成", "user"},
	{"DELETE", "/api/notifications", "清理通知", "集成", "user"},
	{"GET", "/api/views", "保存的筛选视图", "集成", "user"},
	{"POST", "/api/views", "保存筛选视图", "集成", "user"},
	{"DELETE", "/api/views", "删除筛选视图", "集成", "user"},
	{"GET", "/api/system", "运行时与版本信息", "运维", "user"},
	{"GET", "/api/system/environment", "非敏感环境配置", "运维", "admin"},
	{"GET", "/api/system/backup", "下载 SQLite 备份", "运维", "admin"},
	{"POST", "/api/system/purge-logs", "按保留期清理日志", "运维", "admin"},
	{"POST", "/api/system/rotate-jwt", "轮换签名密钥并失效会话", "运维", "admin"},
	{"GET", "/api/export/users.csv", "导出账号 CSV", "运维", "admin"},
	{"GET", "/api/export/users.json", "导出账号 JSON", "运维", "admin"},
	{"GET", "/api/export/config.json", "导出可迁移配置", "运维", "admin"},
	{"GET", "/", "回显请求（任意路径）", "回显", "optional"},
}

// endpointsHandler returns the human-readable endpoint catalogue.
func endpointsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, endpointDocs)
}

// openAPIHandler emits a compact OpenAPI 3 document generated from the same
// catalogue the console renders.
func openAPIHandler(w http.ResponseWriter, r *http.Request) {
	paths := map[string]map[string]any{}
	for _, e := range endpointDocs {
		item := paths[e.Path]
		if item == nil {
			item = map[string]any{}
			paths[e.Path] = item
		}
		op := map[string]any{
			"summary": e.Summary,
			"tags":    []string{e.Group},
			"responses": map[string]any{
				"200": map[string]string{"description": "OK"},
			},
		}
		if e.Auth == "user" || e.Auth == "admin" {
			op["security"] = []map[string][]string{{"BearerAuth": {}}}
		}
		item[lower(e.Method)] = op
	}
	writeJSON(w, map[string]any{
		"openapi": "3.0.3",
		"info": map[string]any{
			"title":       "Echo Server API",
			"version":     serverVersion,
			"description": "HTTP/TLS 指纹回显与请求情报控制台。除公开端点外，使用 Authorization: Bearer <JWT> 或 X-API-Key。",
		},
		"components": map[string]any{
			"securitySchemes": map[string]any{
				"BearerAuth": map[string]string{"type": "http", "scheme": "bearer", "bearerFormat": "JWT"},
				"ApiKeyAuth": map[string]string{"type": "apiKey", "in": "header", "name": "X-API-Key"},
			},
		},
		"paths": paths,
	})
}

func lower(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
}
