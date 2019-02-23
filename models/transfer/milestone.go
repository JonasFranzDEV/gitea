package transfer

type Milestone struct {
	Creator     int64
	Title       string
	Description string
	DueOn       int64
	Closed      bool
}
