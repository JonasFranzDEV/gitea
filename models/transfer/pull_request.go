package transfer

// PullRequest defines the transfer structure of an PullRequest
type PullRequest struct {
	Issue
	PatchURL string
	Patch    string
}
