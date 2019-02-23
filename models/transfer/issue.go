package transfer

// Issue defines the transfer structure of an issue
type Issue struct {
	Index     int64
	Title     string
	User      int64
	Labels    []int64
	Assignees []int64
	Milestone int64
}
