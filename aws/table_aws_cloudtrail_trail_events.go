package aws

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go/service/cloudtrail"
	"github.com/turbot/go-kit/types"
	"github.com/turbot/steampipe-plugin-sdk/plugin"
	"github.com/turbot/steampipe-plugin-sdk/plugin/transform"

	"github.com/turbot/steampipe-plugin-sdk/grpc/proto"
)

type eventSummary struct {
	EventID            string                 `json:"eventID"`
	ReadOnly           string                 `json:"readOnly"`
	AWSRegion          string                 `json:"awsRegion"`
	EventName          string                 `json:"eventName"`
	EventTime          string                 `json:"eventTime"`
	EventType          string                 `json:"eventType"`
	UserAgent          string                 `json:"userAgent"`
	EventSource        string                 `json:"eventSource"`
	EventVersion       string                 `json:"eventVersion"`
	UserIdentity       map[string]interface{} `json:"userIdentity"`
	EventCategory      string                 `json:"eventCategory"`
	ManagementEvent    bool                   `json:"managementEvent"`
	SourceIPAddress    string                 `json:"sourceIPAddress"`
	ResponseElements   map[string]interface{} `json:"responseElements"`
	RequestParameters  map[string]interface{} `json:"requestParameters"`
	RecipientAccountID string                 `json:"recipientAccountId"`
}

func tableAwsCloudtrailEvent(_ context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "aws_cloudtrail_trail_event",
		Description: "AWS CloudTrail Trail Event",
		List: &plugin.ListConfig{
			KeyColumns: plugin.SingleColumn("event_time"),
			Hydrate:    listCloudtrailEvents,
		},
		Columns: awsRegionalColumns([]*plugin.Column{
			{
				Name:        "event_name",
				Description: "The name of the event.",
				Type:        proto.ColumnType_STRING,
			},
			{
				Name:        "event_id",
				Description: "The CloudTrail ID of the event.",
				Type:        proto.ColumnType_STRING,
			},
			{
				Name:        "user_name",
				Description: "A user name or role name of the requester that called the API in the event returned.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("Username"),
			},
			{
				Name:        "event_source",
				Description: "The AWS service that the request was made to.",
				Type:        proto.ColumnType_STRING,
			},
			{
				Name:        "event_time",
				Description: "The date and time of the event returned.",
				Type:        proto.ColumnType_TIMESTAMP,
			},
			{
				Name:        "read_only",
				Description: "Information about whether the event is a write event or a read event.",
				Type:        proto.ColumnType_STRING,
			},
			{
				Name:        "event",
				Description: "A JSON object that contains the event returned.",
				Type:        proto.ColumnType_JSON,
				Transform:   transform.FromField("CloudTrailEvent").Transform(transform.UnmarshalYAML),
			},
			{
				Name:        "resources",
				Description: "A list of resources referenced by the event returned.",
				Type:        proto.ColumnType_STRING,
			},

			// standard steampipe columns
			{
				Name:        "title",
				Description: resourceInterfaceDescription("title"),
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("EventName"),
			},
			// {
			// 	Name:        "akas",
			// 	Description: resourceInterfaceDescription("akas"),
			// 	Type:        proto.ColumnType_JSON,
			// 	Transform:   transform.FromField("TrailARN").Transform(arnToAkas),
			// },
		}),
	}
}

//// LIST FUNCTION

func listCloudtrailEvents(ctx context.Context, d *plugin.QueryData, _ *plugin.HydrateData) (interface{}, error) {
	defaultRegion := GetDefaultRegion()
	plugin.Logger(ctx).Trace("listCloudtrailTrails", "AWS_REGION", defaultRegion)

	// Create session
	svc, err := CloudTrailService(ctx, d.ConnectionManager, defaultRegion)
	if err != nil {
		return nil, err
	}

	evenTime := d.KeyColumnQuals["event_time"].GetStringValue()

	startTime, err := stringToTime(evenTime)
	// startTime, err := stringToTime("2021-02-03T14:37:27Z")
	if err != nil {
		plugin.Logger(ctx).Trace("listCloudtrailTrails", "startTime", startTime)
		return nil, err
	}

	params := &cloudtrail.LookupEventsInput{
		StartTime: startTime,
		LookupAttributes: []*cloudtrail.LookupAttribute{
			{
				AttributeKey:   types.String("ReadOnly"),
				AttributeValue: types.String("false"),
			},
		},
	}

	// List call
	err = svc.LookupEventsPages(
		params,
		func(page *cloudtrail.LookupEventsOutput, isLast bool) bool {
			for _, event := range page.Events {
				d.StreamListItem(ctx, event)
			}
			return !isLast
		},
	)

	return nil, err
}

//// TRANSFORM FUNCTIONS

func stringToTime(value string) (*time.Time, error) {
	str := types.SafeString(value)

	t, err := time.Parse(time.RFC3339, str)
	if err != nil {
		return nil, err
	}

	return &t, nil
}

// Sample event
// {
//   "eventID": "84bbf085-08fe-42ca-b569-a05645237142",
//   "readOnly": false,
//   "awsRegion": "us-east-1",
//   "eventName": "TerminateInstances",
//   "eventTime": "2021-02-03T15:23:59Z",
//   "eventType": "AwsApiCall",
//   "requestID": "c02b9b92-1865-460b-a39d-ee63042c9037",
//   "userAgent": "console.ec2.amazonaws.com",
//   "eventSource": "ec2.amazonaws.com",
//   "eventVersion": "1.08",
//   "userIdentity": {
//     "arn": "arn:aws:sts::013122550996:assumed-role/superuser/sumit@turbot.com-9KZTru5a7YvfJWn5lnJ",
//     "type": "AssumedRole",
//     "accountId": "013122550996",
//     "accessKeyId": "ASIAQGDRKHTKA7F5ILYE",
//     "principalId": "AROAQGDRKHTKH34YYSHIG:sumit@turbot.com-9KZTru5a7YvfJWn5lnJ",
//     "sessionContext": {
//       "attributes": {
//         "creationDate": "2021-02-03T15:20:36Z",
//         "mfaAuthenticated": "false"
//       },
//       "sessionIssuer": {
//         "arn": "arn:aws:iam::013122550996:role/turbot/superuser",
//         "type": "Role",
//         "userName": "superuser",
//         "accountId": "013122550996",
//         "principalId": "AROAQGDRKHTKH34YYSHIG"
//       },
//       "webIdFederationData": {}
//     }
//   },
//   "eventCategory": "Management",
//   "managementEvent": true,
//   "sourceIPAddress": "103.52.247.53",
//   "responseElements": {
//     "instancesSet": {
//       "items": [
//         {
//           "instanceId": "i-0e76291f8e1f7ff99",
//           "currentState": {
//             "code": 32,
//             "name": "shutting-down"
//           },
//           "previousState": {
//             "code": 16,
//             "name": "running"
//           }
//         }
//       ]
//     }
//   },
//   "requestParameters": {
//     "instancesSet": {
//       "items": [
//         {
//           "instanceId": "i-0e76291f8e1f7ff99"
//         }
//       ]
//     }
//   },
//   "recipientAccountId": "013122550996"
// }
