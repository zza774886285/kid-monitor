# kid-monitor v4

家庭平板控制系统 - 时间管理+视频检测

## 功能
- 实时监控平板网络流量
- 视频/游戏活动检测
- 时间限制管理（工作日/寒暑假）
- Web UI管理面板
- HTTP/1.1 协议（兼容anytls等代理）

## 部署
```bash
docker compose up -d
```

## API
- GET `/` - Web UI
- GET `/api/data` - 获取所有数据
- GET `/api/config` - 获取配置
- POST `/api/config` - 更新配置
- POST `/kid-refresh` - 手动刷新
- POST `/kid-adjust` - 调整平板时间
