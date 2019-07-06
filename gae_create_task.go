package security

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	cloudtasks "cloud.google.com/go/cloudtasks/apiv2beta3"
	taskspb "google.golang.org/genproto/googleapis/cloud/tasks/v2beta3"
)

// RegiosterTaskHandler hooks a task handling function with a named task type. Incoming /z/task requests from any
// queue are routed to these functions based on the "type" json field.
func (am *GaeAccessManager) RegisterTaskHandler(name string, handler TaskHandler) {
	if am.taskHandlers == nil {
		am.taskHandlers = make(map[string]TaskHandler)
	}

	am.taskHandlers[name] = handler
}

// RunTaskHandler runs a named task. The name is derived from the "type" value in the json message.
func (am *GaeAccessManager) RunTaskHandler(name string, session Session, message map[string]interface{}) (bool, error) {
	if am.taskHandlers == nil {
		return false, nil
	}
	v, found := am.taskHandlers[name]
	if !found || v == nil {
		return false, nil
	}
	return true, v(session, message)
}

// CreateTask creates a new task in your App Engine queue.
func (a *GaeAccessManager) CreateTask(queueID string, message map[string]interface{}) (string, error) {
	if a.projectId == "" {
		return "", errors.New("Project ID must be specified")
	}
	if a.locationId == "" {
		return "", errors.New("Location ID must be specified")
	}
	if queueID == "" {
		return "", errors.New("Queue ID must be specified")
	}
	if _, ok := message["site"]; ok == false {
		return "", errors.New("Virtual host must be specified using \"site\" field in message")
	}
	if _, ok := message["type"]; ok == false {
		return "", errors.New("Task type must be specified using \"type\" field in message")
	}
	jsonMessage, err := json.Marshal(message)
	if err != nil {
		return "", errors.New("Failed marshalling message to json: " + err.Error())
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

	req.Task.GetAppEngineHttpRequest().Body = []byte(jsonMessage)

	_, err = client.CreateTask(ctx, req)
	if err != nil {
		return "", fmt.Errorf("cloudtasks.CreateTask(%s): %v", queuePath, err)
	}

	return "", nil
}
