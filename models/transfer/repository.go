package transfer

// Repository defines the transfer structure of a repository
type Repository struct {
	Owner        string
	Name         string
	GitURL       string
	Issues       map[int64]*Issue
	PullRequests map[int64]*PullRequest
	Labels       map[int64]*Label
	Milestones   map[int64]*Milestone
}
