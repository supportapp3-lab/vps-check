package model

type Status string

const (
	PASS Status = "pass"
	INFO Status = "info"
	WARN Status = "warn"
	HIGH Status = "high"
	SKIP Status = "skip"
)

type Finding struct {
	ID          string `json:"id"`
	Status      Status `json:"status"`
	Title       string `json:"title"`
	Evidence    string `json:"evidence"`
	Explanation string `json:"explanation"`
	Remediation string `json:"remediation"`
}

type OSInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type Report struct {
	Version   string    `json:"version"`
	OS        OSInfo    `json:"os"`
	Timestamp string    `json:"timestamp"`
	Findings  []Finding `json:"findings"`
}
