def filter_events_by_type(events, event_type):
    matching_events = []

    for event in events:
        if event["event"] == event_type:
            matching_events.append(event)

    return matching_events