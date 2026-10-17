"""A served tool catalog and the queries an agent asks of it (#473).

``benchmarks/tool_search.py`` measures ``find_tools`` on this: for each
query, is the tool that does the job the first result, or in the first
``top_k``? The catalog is invented but of the shape a gateway profile
serves: twenty backends of an operations-and-office agent, short names as
``gateway/names.py`` issues them (a backend tag only where two collide:
``work_``/``home_`` on the two mail accounts), descriptions in the
first-sentence style backends write. No description is copied from a real
server, and no person, address or host is named (constitution XVII).

Queries are worded as an agent asks, by intent, and mostly not in the
tool's own words. ``HELD_OUT`` queries were written with the rest and never
used to tune the ranker (its weights, stop words and synonyms); the
benchmark reports them apart, and a change to the ranker is judged on them.
"""

from __future__ import annotations

from typing import NamedTuple


class Tool(NamedTuple):
    backend: str
    name: str
    description: str


class Query(NamedTuple):
    text: str
    expected: str
    held_out: bool = False


CATEGORIES: dict[str, list[str]] = {
    "mail": ["mail-work", "mail-home"],
    "office": ["calendar", "drive", "sheets", "tasks"],
    "infra": ["monitor", "systemd", "podman", "syslog", "metrics"],
    "web": ["dns", "blog", "web"],
    "dev": ["forge", "tracker", "tickets"],
    "knowledge": ["wiki", "memory"],
    "chat": ["chat"],
}

CATALOG: list[Tool] = [
    # mail-work / mail-home: same tools, so every name collides and is tagged
    *[
        Tool(backend, f"{tag}_{name}", desc)
        for backend, tag in (("mail-work", "work"), ("mail-home", "home"))
        for name, desc in (
            ("search_gmail_messages", "Search messages in the mailbox with a query string."),
            ("get_gmail_message_content", "Get the full content of one message by its id."),
            ("get_gmail_thread_content", "Get every message in a thread."),
            ("send_gmail_message", "Send an email message to one or more recipients."),
            ("draft_gmail_message", "Create a draft email without sending it."),
            ("list_gmail_labels", "List the labels defined in the mailbox."),
            ("modify_gmail_message_labels", "Add or remove labels on a message."),
        )
    ],
    # calendar
    Tool("calendar", "list_calendars", "List the calendars this account can see."),
    Tool("calendar", "get_events", "Get events in a time range from a calendar."),
    Tool("calendar", "manage_event", "Create, update or delete a calendar event."),
    Tool("calendar", "query_freebusy", "Find when attendees are free or busy."),
    Tool("calendar", "manage_out_of_office", "Set or clear an out-of-office period."),
    Tool("calendar", "manage_focus_time", "Block focus time on the calendar."),
    # drive
    Tool("drive", "search_drive_files", "Search files in Drive by name or content."),
    Tool("drive", "get_drive_file_content", "Read a Drive file's content as text."),
    Tool("drive", "create_doc", "Create a new document with optional content."),
    Tool("drive", "get_doc_as_markdown", "Export a document as Markdown."),
    Tool("drive", "modify_doc_text", "Insert or replace text in a document."),
    Tool("drive", "find_and_replace_doc", "Find and replace text throughout a document."),
    Tool("drive", "export_doc_to_pdf", "Export a document to PDF."),
    Tool("drive", "list_docs_in_folder", "List the documents in a Drive folder."),
    Tool("drive", "insert_doc_image", "Insert an image into a document."),
    # sheets
    Tool("sheets", "create_spreadsheet", "Create a new spreadsheet."),
    Tool("sheets", "read_sheet_values", "Read cell values from a range of a sheet."),
    Tool("sheets", "modify_sheet_values", "Write or clear cell values in a range."),
    Tool("sheets", "append_table_rows", "Append rows to a table in a sheet."),
    Tool("sheets", "format_sheet_range", "Apply formatting to a range of cells."),
    Tool("sheets", "list_spreadsheets", "List spreadsheets in the account."),
    # tasks
    Tool("tasks", "list_task_lists", "List the task lists."),
    Tool("tasks", "list_tasks", "List the tasks in a task list."),
    Tool("tasks", "manage_task", "Create, update, complete or delete a task."),
    Tool("tasks", "list_todos", "List todos from a todo list."),
    Tool("tasks", "create_todo", "Add a todo item."),
    Tool("tasks", "complete_todo", "Mark a todo item done."),
    Tool("tasks", "log_pomodoro", "Record a completed pomodoro work session."),
    # monitor
    Tool("monitor", "current_problems", "Hosts and services currently in a problem state."),
    Tool("monitor", "host_status", "Status of one monitored host."),
    Tool("monitor", "service_status", "Status of the services checked on a host."),
    Tool("monitor", "acknowledge", "Acknowledge a host or service problem."),
    Tool("monitor", "schedule_check", "Schedule an immediate re-check of a service."),
    Tool("monitor", "alert_history", "Alerts raised over a time window."),
    Tool("monitor", "notification_history", "Notifications sent to contacts."),
    Tool("monitor", "add_comment", "Add a comment to a host or service."),
    # systemd
    Tool("systemd", "unit_list", "List systemd units and their states."),
    Tool("systemd", "unit_status", "Show the status of one systemd unit."),
    Tool("systemd", "unit_start", "Start a systemd unit."),
    Tool("systemd", "unit_stop", "Stop a systemd unit."),
    Tool("systemd", "unit_restart", "Restart a systemd unit."),
    Tool("systemd", "unit_enable", "Enable a unit to start at boot."),
    Tool("systemd", "unit_file_write", "Write a unit file to disk."),
    Tool("systemd", "daemon_reload", "Reload the systemd manager configuration."),
    Tool("systemd", "failed_units", "List units in the failed state."),
    Tool("systemd", "journal_query", "Query the systemd journal for a unit or time range."),
    Tool("systemd", "hostinfo", "Hostname, kernel and operating system of the host."),
    # podman
    Tool("podman", "container_list", "List containers and their states."),
    Tool("podman", "container_inspect", "Inspect a container's configuration."),
    Tool("podman", "container_logs", "Fetch a container's logs."),
    Tool("podman", "container_stats", "CPU and memory use of running containers."),
    Tool("podman", "container_top", "Processes running inside a container."),
    Tool("podman", "image_list", "List container images."),
    Tool("podman", "image_pull", "Pull a container image from a registry."),
    Tool("podman", "image_prune", "Remove unused container images."),
    Tool("podman", "volume_list", "List container volumes."),
    Tool("podman", "system_df", "Disk space used by images, containers and volumes."),
    # syslog
    Tool("syslog", "syslog_search", "Search the central syslog by text and time."),
    Tool("syslog", "syslog_tail", "The most recent syslog lines from a host."),
    Tool("syslog", "syslog_grep", "Regular expression search over syslog."),
    Tool("syslog", "syslog_sources", "Hosts and programs that send syslog."),
    Tool("syslog", "syslog_stats", "Message counts by host and severity."),
    # metrics
    Tool("metrics", "query_influxdb", "Run a query against the time series database."),
    Tool("metrics", "search_dashboards", "Search dashboards by title."),
    Tool("metrics", "get_dashboard_summary", "Summary of a dashboard's panels."),
    Tool("metrics", "list_datasources", "List configured datasources."),
    # dns
    Tool("dns", "list_zones", "List DNS zones in the account."),
    Tool("dns", "list_dns_records", "List the records in a DNS zone."),
    Tool("dns", "create_dns_record", "Create a DNS record in a zone."),
    Tool("dns", "update_dns_record", "Change an existing DNS record."),
    Tool("dns", "delete_dns_record", "Delete a DNS record."),
    Tool("dns", "purge_cache", "Purge cached content for a zone or URLs."),
    Tool("dns", "list_waf_rules", "List the firewall rules for a zone."),
    Tool("dns", "get_zone_analytics", "Request and traffic analytics for a zone."),
    # blog
    Tool("blog", "create_post", "Create a blog post as a draft or published."),
    Tool("blog", "update_post", "Update a blog post's title, content or status."),
    Tool("blog", "get_post", "Get one blog post by id."),
    Tool("blog", "list_posts", "List recent blog posts."),
    Tool("blog", "search_posts", "Search blog posts by text."),
    Tool("blog", "upload_media", "Upload an image or file to the media library."),
    Tool("blog", "list_categories", "List the blog's categories."),
    Tool("blog", "list_tags", "List the blog's tags."),
    # web (the gateway's own)
    Tool("web", "fetch", "Fetch a URL and return its content."),
    Tool("web", "search", "Search the web and return results with sources."),
    Tool("web", "read", "Read a local text file."),
    Tool("web", "read_part", "Read the next part of a response delivered in parts."),
    # forge
    Tool("forge", "list_pull_requests", "List pull requests in a repository."),
    Tool("forge", "get_pull_request", "Get a pull request's details."),
    Tool("forge", "get_pull_request_diff", "Get the diff of a pull request."),
    Tool("forge", "create_pull_request", "Open a pull request."),
    Tool("forge", "merge_pull_request", "Merge a pull request."),
    Tool("forge", "list_issues", "List issues in a repository."),
    Tool("forge", "github_create_issue", "Create an issue in a repository."),
    Tool("forge", "list_workflow_runs", "List CI workflow runs."),
    Tool("forge", "get_failed_job_logs", "Logs of the failed jobs of a workflow run."),
    Tool("forge", "rerun_failed_jobs", "Re-run the failed jobs of a workflow run."),
    Tool("forge", "create_release", "Create a release from a tag."),
    Tool("forge", "list_repo_tree", "List files in a repository at a ref."),
    Tool("forge", "get_file_content", "Get a file's content from a repository."),
    # tracker
    Tool("tracker", "jira_search", "Search issues with a JQL query."),
    Tool("tracker", "jira_get_issue", "Get one issue by key."),
    Tool("tracker", "jira_create_issue", "Create an issue in a project."),
    Tool("tracker", "jira_update_issue", "Update fields of an issue."),
    Tool("tracker", "jira_add_comment", "Add a comment to an issue."),
    Tool("tracker", "transition_issue", "Move an issue to another workflow status."),
    Tool("tracker", "link_to_epic", "Link an issue to an epic."),
    Tool("tracker", "get_project_issues", "List the issues of a project."),
    # tickets (a helpdesk queue)
    Tool("tickets", "search_tickets", "Search helpdesk tickets."),
    Tool("tickets", "get_ticket", "Get a helpdesk ticket and its history."),
    Tool("tickets", "create_ticket", "Open a helpdesk ticket in a queue."),
    Tool("tickets", "reply_to_ticket", "Reply to the requestor of a ticket."),
    Tool("tickets", "add_ticket_comment", "Add a private comment to a ticket."),
    Tool("tickets", "resolve_ticket", "Resolve a ticket."),
    Tool("tickets", "set_ticket_owner", "Assign a ticket to an owner."),
    Tool("tickets", "add_time_worked", "Add time worked to a ticket."),
    # wiki
    Tool("wiki", "get_page", "Get a wiki page's wikitext."),
    Tool("wiki", "edit_page", "Edit a section of a wiki page."),
    Tool("wiki", "create_page", "Create a wiki page."),
    Tool("wiki", "wiki_search", "Search wiki pages by text."),
    Tool("wiki", "list_recent_changes", "Recent edits across the wiki."),
    Tool("wiki", "list_page_revisions", "Revision history of a wiki page."),
    Tool("wiki", "get_category_members", "Pages in a wiki category."),
    # memory
    Tool("memory", "memory_search", "Search stored memories by meaning."),
    Tool("memory", "memory_store", "Store a new memory with tags."),
    Tool("memory", "memory_update", "Update an existing memory."),
    Tool("memory", "memory_delete", "Delete a memory."),
    Tool("memory", "memory_list", "List memories by tag or date."),
    Tool("memory", "memory_graph", "Related memories as a graph."),
    # chat
    Tool("chat", "list_channels", "List the chat channels you can see."),
    Tool("chat", "get_channel_history", "Recent messages in a channel."),
    Tool("chat", "get_thread_replies", "Replies in a chat thread."),
    Tool("chat", "send_message", "Post a message to a channel or thread."),
    Tool("chat", "search_messages", "Search chat messages."),
    Tool("chat", "get_reactions", "Reactions on a chat message."),
    Tool("chat", "cancel_scheduled_message", "Cancel a scheduled chat message."),
]

QUERIES: list[Query] = [
    # mail
    Query("send an email from my work account", "work_send_gmail_message"),
    Query("search my personal inbox for the plumber invoice", "home_search_gmail_messages"),
    Query("read the whole email thread", "work_get_gmail_thread_content"),
    Query("draft a reply in my work mail but don't send it", "work_draft_gmail_message", True),
    Query("label a home email as receipts", "home_modify_gmail_message_labels", True),
    # calendar
    Query("what meetings do I have tomorrow", "get_events"),
    Query("book a meeting on my calendar", "manage_event"),
    Query("when is everyone available for a call", "query_freebusy", True),
    Query("set vacation out of office", "manage_out_of_office"),
    Query("block time to work without meetings", "manage_focus_time", True),
    # drive / docs / sheets
    Query("find a file in google drive", "search_drive_files"),
    Query("make a new google doc", "create_doc"),
    Query("convert a doc to markdown", "get_doc_as_markdown"),
    Query("replace a phrase everywhere in the document", "find_and_replace_doc", True),
    Query("save the document as a pdf", "export_doc_to_pdf", True),
    Query("read cells from a spreadsheet", "read_sheet_values"),
    Query("add rows to the spreadsheet table", "append_table_rows"),
    Query("write values into a sheet range", "modify_sheet_values", True),
    # tasks
    Query("add a todo to buy milk", "create_todo"),
    Query("mark the todo as finished", "complete_todo", True),
    Query("what tasks are on my list", "list_tasks"),
    Query("record a pomodoro", "log_pomodoro"),
    # infra
    Query("what is broken right now in monitoring", "current_problems"),
    Query("acknowledge the nagios alert", "acknowledge"),
    Query("recheck the web service now", "schedule_check", True),
    Query("restart the nginx service", "unit_restart"),
    Query("which systemd units failed", "failed_units"),
    Query("show journal logs for a unit", "journal_query"),
    Query("reload systemd after editing a unit file", "daemon_reload", True),
    Query("is the unit running", "unit_status", True),
    Query("list running containers", "container_list"),
    Query("show the logs of a container", "container_logs"),
    Query("how much memory are the containers using", "container_stats", True),
    Query("pull a new image", "image_pull"),
    Query("clean up old images to free disk", "image_prune", True),
    Query("disk usage of podman", "system_df"),
    Query("tail syslog on a host", "syslog_tail"),
    Query("grep the logs for a regex", "syslog_grep", True),
    Query("query influx for cpu over the last hour", "query_influxdb"),
    Query("find the grafana dashboard for disk", "search_dashboards", True),
    Query("what kernel is the server running", "hostinfo", True),
    # web
    Query("add a dns A record", "create_dns_record"),
    Query("change the IP of a dns entry", "update_dns_record", True),
    Query("purge the cloudflare cache", "purge_cache"),
    Query("list firewall rules on the zone", "list_waf_rules", True),
    Query("traffic stats for the website domain", "get_zone_analytics", True),
    Query("publish a new blog post", "create_post"),
    Query("edit an existing blog article", "update_post"),
    Query("upload an image to the blog", "upload_media"),
    Query("download a web page", "fetch"),
    Query("search the internet for news", "search"),
    Query("get the next part of that long response", "read_part"),
    # dev
    Query("open a pull request", "create_pull_request"),
    Query("show me the PR diff", "get_pull_request_diff"),
    Query("merge the PR", "merge_pull_request"),
    Query("why did CI fail", "get_failed_job_logs"),
    Query("rerun the failed github actions", "rerun_failed_jobs", True),
    Query("file a github issue", "github_create_issue"),
    Query("cut a release", "create_release", True),
    Query("read a file from the repository", "get_file_content", True),
    Query("search jira with jql", "jira_search"),
    Query("look up jira issue OPS-123", "jira_get_issue"),
    Query("comment on the jira ticket", "jira_add_comment"),
    Query("move the jira issue to in progress", "transition_issue", True),
    Query("attach the story to an epic", "link_to_epic", True),
    Query("open a helpdesk ticket", "create_ticket"),
    Query("reply to the customer on the RT ticket", "reply_to_ticket"),
    Query("close out the helpdesk ticket", "resolve_ticket", True),
    Query("assign the ticket to someone", "set_ticket_owner", True),
    Query("log hours worked on a ticket", "add_time_worked", True),
    # knowledge
    Query("search the wiki", "wiki_search"),
    Query("edit a wiki page section", "edit_page"),
    Query("what changed on the wiki recently", "list_recent_changes", True),
    Query("history of edits to a wiki page", "list_page_revisions", True),
    Query("remember this decision", "memory_store"),
    Query("recall what we decided about the gateway", "memory_search"),
    Query("forget that memory", "memory_delete", True),
    # chat
    Query("post a message in slack", "send_message"),
    Query("read recent messages in the channel", "get_channel_history"),
    Query("search slack for the outage discussion", "search_messages", True),
    Query("read the replies in that thread", "get_thread_replies", True),
]
