{% macro add_link(link, text) -%}
[url={{ link }}]{{ text }}[/url]
{%- endmacro %}

{%- if name %}
Name: {{ name }}
{% endif %}

{%- if podchaser and podchaser.categories %}
Tags: {% for category in podchaser.categories %}{{ category.title | lower | replace(" ", ".") }}{% if not loop.last %}, {% endif %}{% endfor %}
{%- elif podcastindex and podcastindex.categories %}
Tags: {% for category in podcastindex.categories.values() %}{{ category | lower | replace(" ", ".") }}{% if not loop.last %}, {% endif %}{% endfor %}
{%- elif tags %}
Tags: {{ tags }}
{% endif %}

--- Torrent Description ---

[center]
{%- if podchaser %}
{%- if podchaser.networks and podchaser.networks[0].title %}
[size=10][b]--- {{ podchaser.networks[0].title | upper }} PRESENTS ---[/b][/size]
{%- endif %}

{%- if podchaser.author.name %}
[b][size=10]{{ podchaser.author_article | upper }}[/size] [size=14]{{ podchaser.author.name | upper }}[/size] [size=10]PRODUCTION[/size][/b]
{%- endif %}
[size=30][b]{{ podchaser.title }}[/b][/size]
[i]{%- if podchaser.description_formatted %}{{ podchaser.description_formatted }}{%- else %}{{ podchaser.description }}{%- endif %}[/i]

{% if podchaser.webUrl %}{{ add_link(podchaser.webUrl, 'Official Website') }}{%- endif %}
{%- if podchaser.rssUrl %} | {{ add_link(podchaser.rssUrl, 'RSS Feed') }}{%- endif %}
{%- if podchaser.spotifyId %} | {{ add_link('https://open.spotify.com/show/' ~ podchaser.spotifyId, 'Spotify') }}{%- endif %}
{%- if podchaser.applePodcastsId %} | {{ add_link('https://podcasts.apple.com/us/podcast/id' ~ podchaser.applePodcastsId, 'Apple Podcasts') }}{%- endif %}
{%- if podchaser.url %} | {{ add_link(podchaser.url, 'Podchaser') }}{%- endif %}
{%- if podnews and podnews.url %} | {{ add_link(podnews.url, 'Podnews') }}{%- endif %}
{%- if podcastindex and podcastindex.id %} | {{ add_link('https://podcastindex.org/podcast/' ~ podcastindex.id, 'Podcastindex') }}{% endif %}

{% if file_format %}File Format: [b]{{ file_format }}[/b]{%- endif %}
{%- if overall_bitrate %} -- Overall Bitrate: [b]{{ overall_bitrate }}[/b]{%- endif %}
{%- if number_of_files %} -- Number of Episodes: [b]{{ number_of_files }}[/b]{% endif %}
{% if podchaser.avgEpisodeLength %}Average Episode Length: [b]{{ (podchaser.avgEpisodeLength / 60) | round(0) | int }} mins[/b]{%- endif %}

{%- if podchaser.startDate %}
{%- if podchaser.startDate[:10] == podchaser.latestEpisodeDate[:10] %} -- Date: [b]{{ podchaser.startDate[:10] }}[/b]
{%- else %} -- Start Date: [b]{{ podchaser.startDate[:10] }}[/b]
    {%- if podchaser.latestEpisodeDate and not podchaser.status == 'ACTIVE' %} -- End Date: [b]{{ podchaser.latestEpisodeDate[:10] }}[/b]
    {%- elif last_episode_included %} -- Last Episode Included: [b]{{ last_episode_included }}[/b]
    {%- endif %}
{%- endif %}
{%- endif %}

{%- if podnews and podnews.appleRating %}

Apple Podcasts Rating: [b]{{ podnews.appleRating }}[/b] ({{ podnews.appleRatingCount }} votes){%- endif %}
{%- if podchaser.ratingAverage %}{%- if podnews and podnews.appleRating %} -- {%- else %}

{% endif %} Podchaser Rating: [b]{{ podchaser.ratingAverage }}[/b] ({{ podchaser.ratingCount }} votes){%- endif %}
{%- elif podcastindex %}
{%- if podcastindex.author %}
[b][size=10]{{ podcastindex.author_article | upper }}[/size] [size=14]{{ podcastindex.author | upper }}[/size] [size=10]PRODUCTION[/size][/b]
{%- endif %}
[size=30][b]{{ podcastindex.title }}[/b][/size]
[i]{%- if podcastindex.description_formatted %}{{ podcastindex.description_formatted }}{%- else %}{{ podcastindex.description }}{%- endif %}[/i]

{% if podcastindex.link %}{{ add_link(podcastindex.link, 'Official Website') }}{%- endif %}
{%- if podcastindex.url %} | {{ add_link(podcastindex.url, 'RSS Feed') }}{%- endif %}
{%- if podcastindex.itunesId %} | {{ add_link('https://podcasts.apple.com/us/podcast/id' ~ podcastindex.itunesId, 'Apple Podcasts') }}{%- endif %}
{%- if podnews and podnews.url %} | {{ add_link(podnews.url, 'Podnews') }}{%- endif %}
{%- if podcastindex and podcastindex.id %} | {{ add_link('https://podcastindex.org/podcast/' ~ podcastindex.id, 'Podcastindex') }}{% endif %}

{% if file_format %}File Format: [b]{{ file_format }}[/b]{%- endif %}
{%- if overall_bitrate %} -- Overall Bitrate: [b]{{ overall_bitrate }}[/b]{%- endif %}
{%- if number_of_files %} -- Number of Episodes: [b]{{ number_of_files }}[/b]{% endif %}
{% if last_episode_included %}Last Episode Included: [b]{{ last_episode_included }}[/b]{%- endif %}
{%- if podnews and podnews.appleRating %}
{%- if last_episode_included %} -- {% endif %}Apple Podcasts Rating: [b]{{ podnews.appleRating }}[/b] ({{ podnews.appleRatingCount }} votes)
{%- endif %}
{%- else %}
[size=30][b]{{ name_clean }}[/b][/size]
{%- if description %}[i]{{ description }}[/i]{% endif %}
{%- if links %}{{ links }}{% endif %}
{% if file_format %}File Format: [b]{{ file_format }}[/b]{%- endif %}
{%- if overall_bitrate %} -- Overall Bitrate: [b]{{ overall_bitrate }}[/b]{%- endif %}
{%- if number_of_files %} -- Number of Episodes: [b]{{ number_of_files }}[/b]{% endif %}
{% if last_episode_included %}Last Episode Included: [b]{{ last_episode_included }}[/b]{%- endif %}
{%- if podnews and podnews.appleRating %}
{%- if last_episode_included %} -- {%- endif %} Apple Podcasts Rating: [b]{{ podnews.appleRating }}[/b] ({{ podnews.appleRatingCount }} votes)
{%- endif %}
{%- endif %}

{%- if bitrate_breakdown or differing_bitrates or file_format_breakdown or differing_file_formats %}

{%- if bitrate_breakdown %}This upload has files with mixed bitrates.
[spoiler][code]{{ bitrate_breakdown }}[/code][/spoiler]
{%- endif %}
{%- if differing_bitrates %}These files are not {{ overall_bitrate }}:
[spoiler][code]{{ differing_bitrates }}[/code][/spoiler]
{%- endif %}
{%- if file_format_breakdown %}This upload has files in mixed file formats.
[spoiler][code]{{ file_format_breakdown }}[/code][/spoiler]
{%- endif %}
{%- if differing_file_formats %}These files are not {{ file_format }}:
[spoiler][code]{{ differing_file_formats }}[/code][/spoiler]
{%- endif %}
{%- endif %}

[size=10]Powered by [url=https://github.com/lewler/bulldozer]Bulldozer[/url] - Breaking Down Walls™ Since 2024[/size]
[/center]

--- Torrent Description ---