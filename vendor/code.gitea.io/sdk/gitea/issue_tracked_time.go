// Copyright 2017 The Gitea Authors. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package gitea

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"
)

// TrackedTime worked time for an issue / pr
// swagger:response TrackedTime
type TrackedTime struct {
	ID      int64     `json:"id"`
	Created time.Time `json:"created"`
	// Time in seconds
	Time    int64 `json:"time"`
	UserID  int64 `json:"user_id"`
	IssueID int64 `json:"issue_id"`
}

// TrackedTimes represent a list of tracked times
// swagger:response TrackedTimes
type TrackedTimes []*TrackedTime

// GetUserTrackedTimes list tracked times of a user
func (c *Client) GetUserTrackedTimes(user string) ([]*TrackedTime, error) {
	times := make([]*TrackedTime, 0, 10)
	return times, c.getParsedResponse("GET", fmt.Sprintf("/users/%s/times", user), nil, nil, &times)
}

// GetMyTrackedTimes list tracked times of the current user
func (c *Client) GetMyTrackedTimes() ([]*TrackedTime, error) {
	times := make([]*TrackedTime, 0, 10)
	return times, c.getParsedResponse("GET", "/user/times", nil, nil, &times)
}

// AddTimeOption adds time manually to an issue
// swagger:response AddTimeOption
type AddTimeOption struct {
	Time int64 `json:"time" binding:"Required"`
}

// AddTime adds time to issue with the given index
func (c *Client) AddTime(owner, repo string, index int64, opt AddTimeOption) (*TrackedTime, error) {
	body, err := json.Marshal(&opt)
	if err != nil {
		return nil, err
	}
	t := new(TrackedTime)
	return t, c.getParsedResponse("POST", fmt.Sprintf("/repos/%s/%s/issues/%d/times", owner, repo, index),
		jsonHeader, bytes.NewReader(body), t)
}

// ListTrackedTimes get tracked times of one issue via issue id
func (c *Client) ListTrackedTimes(owner, repo string, index int64) ([]*TrackedTime, error) {
	times := make([]*TrackedTime, 0, 5)
	return times, c.getParsedResponse("GET", fmt.Sprintf("/repos/%s/%s/issues/%d/times", owner, repo, index), nil, nil, &times)
}
