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

func tableAwsCloudtrailEvent(_ context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "aws_cloudtrail_trail_event",
		Description: "AWS CloudTrail Trail Event",
		Get: &plugin.GetConfig{
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

	startTime, err := stringToTime(d.KeyColumnQuals["event_time"].GetStringValue())
	if err != nil {
		plugin.Logger(ctx).Trace("listCloudtrailTrails", "startTime", startTime)
		return nil, err
	}

	params := &cloudtrail.LookupEventsInput{
		StartTime: startTime,
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
