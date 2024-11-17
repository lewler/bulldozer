# template.py
from jinja2 import Template
from .utils import log

class ReportTemplate:
    def __init__(self, podcast, config):
        """
        Initialize the ReportTemplate with the podcast and configuration.

        :param podcast: The podcast object containing information about the podcast.
        :param config: The configuration settings.

        The ReportTemplate class is responsible for rendering the report template.
        """
        self.podcast = podcast
        self.config = config
        self.template_file = config.get('template_file', 'default')
        self.name_template_file = config.get('name_template_file', 'default')
        self.template = None
        with open(f"templates/{self.template_file}.tpl", "r") as template_file:
            self.template = Template(template_file.read())
        if not self.template:
            log(f"Template {self.template_file} not found. Will only include description.", "warning")
            self.template = Template("{{ description }}")
        with open(f"templates/{self.name_template_file}.tpl", "r") as template_file:
            self.name_template = Template(template_file.read())
        if not self.name_template:
            log(f"Template {self.template_file} not found. Name will only be podcast name.", "warning")
            self.name_template = Template("{{ podcast_name }}")
        self.link_template = Template(config.get('link_template', '{{ link }}'))
        self.links_section_template = Template(config.get('links_section_template', '{{ links }}'))

    def get_name(self, data):
        """
        Generates the name string using the name template and provided data.

        :param data: A dictionary containing key-value pairs that match placeholders in the template.
        :return: A string with the formatted name.
        """
        return self.name_template.render(data)
    
    def get_links(self, links):
        """
        Generates the name string using the name template and provided data.

        :param links: A dictionary containing key-value pairs that match placeholders in the template.
        :return: A string with the formatted links section.
        """
        links_str = ""
        for key, value in links.items():
            links_str += self.link_template.render({"link": value, "text": key}) + "\n"
        data = {
            "links": links_str[:-1]
        }
        return self.links_section_template.render(data)

    def render(self, data):
        """
        Renders the template with the provided data.

        :param data: A dictionary containing key-value pairs that match placeholders in the template.
        :return: A string containing the rendered template.
        """
        return self.template.render(data)
