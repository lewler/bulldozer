{{ name_clean }}
{%- if completed %} (Complete)
{%- endif -%}
{{ premium_show }} [
{%- if first_episode_date_str == real_first_episode_date_str -%}
{{ start_year_str }}
{%- elif first_episode_date_str -%}
{{ first_episode_date_str }}
{%- endif %}
{%- if (last_episode_date_str == real_last_episode_date_str and completed) or not last_episode_date_str == real_last_episode_date_str -%}
-{{ end_year_str }}
{%- elif last_episode_date_str -%}
{{ last_episode_date_str }}
{%- endif -%}
/{{ file_format }}-{{ overall_bitrate }}]