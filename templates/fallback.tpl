{%- if name %}
Name: {{ name }}
{% endif %}
{%- if tags %}
Tags: {{ tags }}
{% endif %}

--- Torrent Description ---
[center]
[size=30][b]{{ name_clean }}[/b][/size]
{%- if description %}
[i]{{ description }}[/i]
{% endif %}
{%- if links %}
{{ links }}
{% endif %}
{% if file_format %}File Format: [b]{{ file_format }}[/b]{%- endif %}
{%- if overall_bitrate %} -- Overall Bitrate: [b]{{ overall_bitrate }}[/b]{%- endif %}
{%- if number_of_files %} -- Number of Episodes: [b]{{ number_of_files }}[/b]{% endif %}
{% if first_episode_date_str %}
{%- if first_episode_date_str == last_episode_date_str -%}
Date: [b]{{ first_episode_date_str }}[/b]
{%- else -%}
{%- if first_episode_date_str == real_first_episode_date_str -%}
Start Date
{%- else -%}
First Episode Included
{%- endif %}: [b]{{ first_episode_date_str }}[/b]
{%- if last_episode_date_str %} -- {% if completed %}End Date{% else %}Last Episode Included{% endif %}: [b]{{ last_episode_date_str }}[/b]{%- endif %}
{%- endif %}
{%- endif %}
{%- if average_duration %}{%- if first_episode_date_str %} -- {% endif %}Average Episode Length: [b]{{ (average_duration / 60) | round(0) | int }} mins[/b]{%- endif %}
[/center]

{%- if bitrate_breakdown %}
This upload has files with mixed bitrates.[spoiler][code]{{ bitrate_breakdown }}[/code][/spoiler]
{%- endif %}
{%- if differing_bitrates %}
These files are not {{ overall_bitrate }}:[spoiler][code]{{ differing_bitrates }}[/code][/spoiler]
{%- endif %}
{%- if file_format_breakdown %}
This upload has files in mixed file formats.[spoiler][code]{{ file_format_breakdown }}[/code][/spoiler]
{%- endif %}
{%- if differing_file_formats %}
These files are not {{ file_format }}:[spoiler][code]{{ differing_file_formats }}[/code][/spoiler]
{%- endif %}

{%- if upload_notes %}
{{ upload_notes }}
{%- endif %}

[size=10]Powered by [url=https://github.com/lewler/bulldozer]Bulldozer[/url] - Breaking Down Walls™ Since 2024[/size]
--- Torrent Description ---
