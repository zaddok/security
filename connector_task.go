package security

import (
	"fmt"
)

func connectorTask(am AccessManager) func(session Session, message map[string]interface{}) error {
	return func(session Session, message map[string]interface{}) error {
		scheduledconnector := message["scheduledconnector"].(string)
		connector, err := am.GetScheduledConnector(scheduledconnector, session)
		if err != nil {
			am.Error(session, `connector`, "Task(%s): error looking up scheduled connector: %s", message["type"].(string), err)
			fmt.Printf("Task(%s): error looking up scheduled connector: %s\n", message["type"].(string), err)
			return nil
		}
		if connector == nil {
			am.Error(session, `connector`, "Task(%s): connector not found. Uuid: %s Site: %s", message["type"].(string), scheduledconnector, session.Site())
			fmt.Printf("Task(%s): connector not found. Uuid: %s Site: %s\n", message["type"].(string), scheduledconnector, session.Site())
			return nil
		}
		found := am.GetConnectorInfoByLabel(connector.Label)
		if found != nil {
			if found.Run == nil {
				am.Error(session, `connector`, "Task(%s): failed: no run function for %s", message["type"].(string), connector.Label)
				return nil
			}

			err := found.Run(am, connector, session)
			if err != nil {
				fmt.Printf("Task(%s) failed. %s\n", message["type"].(string), err)
				am.Error(session, `connector`, "Task(%s) failed", message["type"].(string), err)
				return nil
			}
			am.Error(session, `connector`, "Task(%s) success", message["type"].(string))
			return nil
		} else {
			fmt.Printf("Task(%s): Scheduled connector contains unknown connector type label: %s", message["type"].(string), connector.Label)
			am.Notice(session, `connector`, "Task(%s): Scheduled connector contains unknown connector type label: %s", message["type"].(string), connector.Label)
			return nil
		}
	}
}
