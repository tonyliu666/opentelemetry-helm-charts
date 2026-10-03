# Code Graph Delta Extractor for K8s Auditor

## 📌 專案概述 (Overview)
**目標**：開發一個輕量級的 Python 腳本 `get-graph-delta.py`。
**用途**：作為 Git `pre-push` hook 與 AI LLM CLI 之間的中介層。
**核心行為**：
1. 接收 `helm template` 的輸出 (YAML)。
2. 提取出 Kubernetes 資源的關鍵欄位（剔除雜訊）。
3. 與本地的 SQLite 資料庫 (`.codegraph/codegraph.db`) 進行 Hash 比對，找出「本次變更」的節點（Nodes）。
4. 計算受影響的關聯（Edges），例如 Service Selector 與 Deployment Labels 的關聯。
5. 輸出極簡的 JSON 格式 (Delta Payload) 供 AI Skill 進行秒級安全審計。

---

## 🛠️ 技術選型與依賴 (Tech Stack & Dependencies)
* **語言**：Python 3.8+ (無須複雜環境，適合 Local 執行)
* **核心依賴**：
  * `PyYAML` (用於解析 Helm 產出的多重 YAML 文件)
* **內建標準庫**：
  * `sqlite3` (本地輕量資料庫操作)
  * `hashlib` (計算資源狀態 Hash，判斷是否變更)
  * `json`, `sys`, `argparse`

---

## 🗄️ 模組 1：資料庫 Schema 設計 (SQLite)
在 `.codegraph/codegraph.db` 中建立極簡的拓撲狀態表：

| 表名 (Table) | 欄位 (Columns) | 說明 |
| :--- | :--- | :--- |
| `nodes` | `id` (PK, TEXT) | 節點唯一識別碼 (例：`Deployment/my-app`) |
| | `kind` (TEXT) | 資源類型 (Deployment, Service, etc.) |
| | `name` (TEXT) | 資源名稱 |
| | `hash` (TEXT) | 內容的 SHA256 (用於判斷是否變更) |
| | `details` (JSON) | AI 審計需要的關鍵欄位 (JSON 字串) |

> *註：為了保持輕量，Edges 不一定要存入 DB，可以在腳本執行當下依據 Nodes 的 labels/selectors 動態計算。*

---

## ⚙️ 模組 2：YAML 解析與特徵萃取 (Feature Extraction)
實作一個解析器，針對不同 Kubernetes `kind` 只抓取 AI Skill 需要的欄位，其餘一律捨棄：

1. **Workloads (Deployment, StatefulSet, DaemonSet)**
   * `metadata.labels`
   * `spec.template.spec.containers[].resources` (Request / Limits 比例審計)
   * `spec.template.spec.containers[].securityContext` (特權與安全審計)
2. **Networking (Service)**
   * `spec.selector` (Dangling Service 審計)
   * `spec.ports` (Port 對齊審計)
3. **Scaling (HorizontalPodAutoscaler, KEDA ScaledObject)**
   * `spec.scaleTargetRef` (確保目標存在)

---

## 🔄 模組 3：Delta 計算邏輯 (Delta Computation)
這是腳本加速的核心，實作流程如下：

1. **讀取與解析**：從 `stdin` 或 `--file` 讀取 `rendered.yaml`，轉為 Python 字典。
2. **建構當前狀態**：將解析後的特定欄位轉為 JSON 字串，並計算 SHA256 Hash。
3. **比對 DB (增量判斷)**：
   * `SELECT hash FROM nodes WHERE id = ?`
   * 如果 Hash 不同（或 DB 沒這筆資料） ➡️ **標記為 Changed Node**。
4. **關聯追蹤 (Impact Analysis)**：
   * 如果 `Service A` 變更了，連帶把被它 Selector 圈中的 `Deployment B` 一併加入 Delta。
   * 如果 `Deployment B` 變更了，連帶把指向它的 `Service A` 一併加入 Delta。
5. **更新 DB**：將最新狀態寫回 SQLite（`INSERT OR REPLACE`）。

---

## 📤 模組 4：輸出結構化 JSON (Payload Generation)
最後，將變更的部分輸出成標準 JSON 到 `stdout`。這個結構必須完美契合 `k8s-pre-release-auditor` 的 Skill 設計。

**預期產出格式範例：**
```json
{
  "audit_scope": "local-delta",
  "changed_nodes": [
    {
      "id": "Deployment/backend",
      "kind": "Deployment",
      "name": "backend",
      "details": {
        "labels": {"app": "backend"},
        "containers": [
          {
            "name": "api",
            "cpu_limit": "2000m",
            "cpu_request": "100m"
          }
        ]
      }
    }
  ],
  "impacted_edges": [
    {
      "relation": "Service/backend-svc -> selects -> Deployment/backend",
      "service_selector": {"app": "backend-typo"}
    }
  ]
}