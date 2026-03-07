{%- if name %}
Name: {{ name }}
{% endif %}
{%- if tags %}
Tags: {{ tags }}
{% endif %}

--- Torrent Description ---

{%- if description %}
[b]Official Description[/b]
[quote]{{ description }}[/quote]
{% endif %}
{%- if last_episode_date %}
[b]Last Episode Included[/b]
{{ last_episode_date }}
{% endif %}
{%- if bitrate_breakdown %}
[b]Bitrate Breakdown[/b]
[spoiler][code]
{{ bitrate_breakdown }}
[/code][/spoiler]
{% endif %}
{%- if differing_bitrates %}
[b]Differing Bitrates[/b]
[spoiler][code]
{{ differing_bitrates }}
[/code][/spoiler]
{% endif %}
{%- if file_format_breakdown %}
[b]File Format Breakdown[/b]
[spoiler][code]
{{ file_format_breakdown }}
[/code][/spoiler]
{% endif %}
{%- if differing_file_formats %}
[b]Differing File Formats[/b]
[spoiler][code]
{{ differing_file_formats }}
[/code][/spoiler]
{% endif %}
{%- if links %}
{{ links }}
{% endif %}
{%- if upload_notes %}
{{ upload_notes }}
{% endif %}

--- Torrent Description ---
