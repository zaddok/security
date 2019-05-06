package security

import (
	"context"
	"errors"
	"fmt"

	cloudtasks "cloud.google.com/go/cloudtasks/apiv2beta3"
	taskspb "google.golang.org/genproto/googleapis/cloud/tasks/v2beta3"
)

// CreateTask creates a new task in your App Engine queue.
func (a *GaeAccessManager) CreateTask(queueID, message string) (string, error) {
	if a.projectId == "" {
		return "", errors.New("Project ID must be specified")
	}
	if a.locationId == "" {
		return "", errors.New("Location ID must be specified")
	}
	if queueID == "" {
		return "", errors.New("Queue ID must be specified")
	}

	// Create a new Cloud Tasks client instance.
	// See https://godoc.org/cloud.google.com/go/cloudtasks/apiv2beta3
	ctx := context.Background()
	client, err := cloudtasks.NewClient(ctx)
	if err != nil {
		return "", fmt.Errorf("NewClient: %v", err)
	}

	// Build the Task queue path.
	queuePath := fmt.Sprintf("projects/%s/locations/%s/queues/%s", a.projectId, a.locationId, queueID)

	a.Log().Debug("About to submit task to: %s", queuePath)

	// Build the Task payload.
	// https://godoc.org/google.golang.org/genproto/googleapis/cloud/tasks/v2beta3#CreateTaskRequest
	req := &taskspb.CreateTaskRequest{
		Parent: queuePath,
		Task: &taskspb.Task{
			// https://godoc.org/google.golang.org/genproto/googleapis/cloud/tasks/v2beta3#AppEngineHttpRequest
			PayloadType: &taskspb.Task_AppEngineHttpRequest{
				AppEngineHttpRequest: &taskspb.AppEngineHttpRequest{
					HttpMethod:  taskspb.HttpMethod_POST,
					RelativeUri: "/z/task",
				},
			},
		},
	}

	// Add a payload message if one is present.
	if message != "" {
		req.Task.GetAppEngineHttpRequest().Body = []byte(message)
	}

	_, err = client.CreateTask(ctx, req)
	if err != nil {
		return "", fmt.Errorf("cloudtasks.CreateTask(%s): %v", queuePath, err)
	}

	return "", nil
}
