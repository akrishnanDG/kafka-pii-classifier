"""Report generation for PII classification results."""

import json
import logging
from html import escape as html_escape
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime

from ..utils.helpers import mask_pii

logger = logging.getLogger(__name__)


class ReportGenerator:
    """Generate reports from PII classification results."""

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize report generator.

        Args:
            config: Reporting configuration
        """
        self.config = config
        self.output_dir = Path(config.get('output_directory', './reports'))
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.formats = config.get('output_format', ['json'])
        self.include_samples = config.get('include_samples', False)

    def generate(self, results: Dict[str, Any]) -> List[Path]:
        """
        Generate reports in configured formats.

        Args:
            results: Analysis results dictionary

        Returns:
            List of generated report file paths
        """
        generated_files = []

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

        for format_type in self.formats:
            if format_type == 'json':
                file_path = self._generate_json(results, timestamp)
                if file_path:
                    generated_files.append(file_path)
            elif format_type == 'html':
                file_path = self._generate_html(results, timestamp)
                if file_path:
                    generated_files.append(file_path)
            else:
                logger.warning(f"Unknown report format: {format_type}")

        return generated_files

    def _mask_sample_values(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Mask PII sample values in results before writing to reports."""
        import copy
        masked = copy.deepcopy(results)

        for topic_result in masked.get('topics_analyzed', []):
            classifications = topic_result.get('classifications', {})
            for field_path, cls in classifications.items():
                if 'sample_values' in cls:
                    if self.include_samples:
                        cls['sample_values'] = [
                            mask_pii(str(v), keep_last=4) for v in cls['sample_values']
                        ]
                    else:
                        cls['sample_values'] = []

        return masked

    def _generate_json(self, results: Dict[str, Any], timestamp: str) -> Optional[Path]:
        """Generate JSON report."""
        try:
            filename = f"pii_classification_report_{timestamp}.json"
            file_path = self.output_dir / filename

            masked_results = self._mask_sample_values(results)

            # Add metadata
            report_data = {
                'timestamp': datetime.now().isoformat(),
                'summary': {
                    'topics_analyzed': len(masked_results.get('topics_analyzed', [])),
                    'total_fields_classified': masked_results.get('total_fields_classified', 0),
                    'total_pii_fields': masked_results.get('total_pii_fields', 0),
                    'errors': len(masked_results.get('errors', []))
                },
                'topics': masked_results.get('topics_analyzed', []),
                'errors': masked_results.get('errors', [])
            }

            with open(file_path, 'w') as f:
                json.dump(report_data, f, indent=2)

            logger.info(f"JSON report generated: {file_path}")
            return file_path

        except Exception as e:
            logger.error(f"Failed to generate JSON report: {e}")
            return None

    def _generate_html(self, results: Dict[str, Any], timestamp: str) -> Optional[Path]:
        """Generate HTML report."""
        try:
            filename = f"pii_classification_report_{timestamp}.html"
            file_path = self.output_dir / filename

            masked_results = self._mask_sample_values(results)
            html_content = self._build_html(masked_results)

            with open(file_path, 'w') as f:
                f.write(html_content)

            logger.info(f"HTML report generated: {file_path}")
            return file_path

        except Exception as e:
            logger.error(f"Failed to generate HTML report: {e}")
            return None

    def _build_html(self, results: Dict[str, Any]) -> str:
        """Build HTML report content."""
        summary = {
            'topics_analyzed': len(results.get('topics_analyzed', [])),
            'total_fields_classified': results.get('total_fields_classified', 0),
            'total_pii_fields': results.get('total_pii_fields', 0),
            'errors': len(results.get('errors', []))
        }

        # Separate topics into categories
        topics_with_pii = []
        topics_with_data = []
        empty_topics = []

        for topic_result in results.get('topics_analyzed', []):
            samples = topic_result.get('samples', 0)
            pii_fields = topic_result.get('pii_fields_found', 0)

            if pii_fields > 0:
                topics_with_pii.append(topic_result)
            elif samples > 0:
                topics_with_data.append(topic_result)
            else:
                empty_topics.append(topic_result)

        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>PII Classification Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; }}
        h1 {{ color: #333; }}
        h2 {{ color: #666; border-bottom: 2px solid #ddd; padding-bottom: 10px; }}
        .summary {{ background: #f9f9f9; padding: 15px; border-radius: 5px; margin: 20px 0; }}
        .summary-grid {{ display: grid; grid-template-columns: repeat(2, 1fr); gap: 15px; margin: 15px 0; }}
        .summary-item {{ padding: 10px; background: white; border-radius: 3px; }}
        .summary-item strong {{ display: block; color: #666; font-size: 0.9em; }}
        .summary-item .value {{ font-size: 1.5em; font-weight: bold; color: #333; }}
        .topic {{ margin: 20px 0; padding: 15px; background: #f9f9f9; border-left: 4px solid #4CAF50; }}
        .topic-empty {{ margin: 5px 0; padding: 8px; background: #f5f5f5; border-left: 2px solid #ccc; }}
        .field {{ margin: 10px 0; padding: 10px; background: white; border: 1px solid #ddd; }}
        .tags {{ display: inline-block; margin: 2px; padding: 4px 8px; background: #e3f2fd; border-radius: 3px; font-size: 0.9em; }}
        .error {{ color: #d32f2f; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background-color: #4CAF50; color: white; }}
        .empty-topics-list {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
            gap: 5px;
            margin: 10px 0;
            font-size: 0.9em;
            color: #666;
        }}
        .empty-topics-list div {{ padding: 4px 8px; background: #f9f9f9; border-radius: 3px; }}
        .collapsible {{ cursor: pointer; }}
        .collapsible-content {{ display: none; }}
        .collapsible-content.active {{ display: block; }}
    </style>
    <script>
        function toggleSection(id) {{
            const content = document.getElementById(id);
            content.classList.toggle('active');
        }}
    </script>
</head>
<body>
    <div class="container">
        <h1>PII Classification Report</h1>
        <p>Generated: {html_escape(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}</p>

        <div class="summary">
            <h2>Summary</h2>
            <div class="summary-grid">
                <div class="summary-item">
                    <strong>Topics Analyzed</strong>
                    <div class="value">{summary['topics_analyzed']}</div>
                </div>
                <div class="summary-item">
                    <strong>Topics with PII</strong>
                    <div class="value">{len(topics_with_pii)}</div>
                </div>
                <div class="summary-item">
                    <strong>Topics with Data (No PII)</strong>
                    <div class="value">{len(topics_with_data)}</div>
                </div>
                <div class="summary-item">
                    <strong>Empty Topics</strong>
                    <div class="value">{len(empty_topics)}</div>
                </div>
                <div class="summary-item">
                    <strong>Fields Classified</strong>
                    <div class="value">{summary['total_fields_classified']}</div>
                </div>
                <div class="summary-item">
                    <strong>PII Fields Found</strong>
                    <div class="value">{summary['total_pii_fields']}</div>
                </div>
            </div>
            {f'<div class="summary-item"><strong>Errors:</strong> {summary["errors"]}</div>' if summary['errors'] > 0 else ''}
        </div>
"""

        # Add topics with PII prominently
        if topics_with_pii:
            html += "<h2>Topics with PII Detected</h2>\n"
            for topic_result in topics_with_pii:
                topic = html_escape(str(topic_result.get('topic', 'Unknown')))
                samples = topic_result.get('samples', 0)
                pii_fields = topic_result.get('pii_fields_found', 0)
                schemaless = topic_result.get('schemaless', False)

                html += f"""
        <div class="topic">
            <h3>{topic}</h3>
            <p><strong>Samples:</strong> {samples} | <strong>PII Fields:</strong> {pii_fields} | <strong>Schemaless:</strong> {'Yes' if schemaless else 'No'}</p>
"""

                classifications = topic_result.get('classifications', {})
                if classifications:
                    html += "<table><tr><th>Field</th><th>PII Types</th><th>Tags</th><th>Confidence</th><th>Detection Rate</th><th>Sample Values</th></tr>\n"
                    for field_path, cls in classifications.items():
                        pii_types = html_escape(', '.join(cls.get('pii_types', [])))
                        tags = ' '.join([f'<span class="tags">{html_escape(tag)}</span>' for tag in cls.get('tags', [])])
                        confidence = cls.get('confidence', 0)
                        detection_rate = cls.get('detection_rate', 0)
                        sample_values = cls.get('sample_values', [])

                        # Format sample values (already masked, truncate long values)
                        if sample_values:
                            display_values = []
                            for val in sample_values[:5]:
                                val_str = html_escape(str(val))
                                if len(val_str) > 50:
                                    val_str = val_str[:47] + '...'
                                display_values.append(val_str)
                            sample_values_str = '<br>'.join([f'<code>{v}</code>' for v in display_values])
                            if len(sample_values) > 5:
                                sample_values_str += f'<br><em>(+{len(sample_values) - 5} more)</em>'
                        else:
                            sample_values_str = '<em>No samples</em>'

                        html += f"""
                    <tr>
                        <td>{html_escape(str(field_path))}</td>
                        <td>{pii_types}</td>
                        <td>{tags}</td>
                        <td>{confidence:.2f}</td>
                        <td>{detection_rate:.1%}</td>
                        <td style="font-size: 0.85em; max-width: 300px; word-wrap: break-word;">{sample_values_str}</td>
                    </tr>
"""
                    html += "</table>\n"

                html += "</div>\n"

        # Add topics with data but no PII (brief)
        if topics_with_data:
            html += f"<h2>Topics with Data (No PII) - {len(topics_with_data)} topics</h2>\n"
            html += "<div class='empty-topics-list'>\n"
            for topic_result in topics_with_data:
                topic = html_escape(str(topic_result.get('topic', 'Unknown')))
                samples = topic_result.get('samples', 0)
                html += f"<div>{topic} ({samples} samples)</div>\n"
            html += "</div>\n"

        # Add empty topics (collapsible)
        if empty_topics:
            html += f"""
        <h2 class="collapsible" onclick="toggleSection('empty-topics')">
            Empty Topics - {len(empty_topics)} topics &#9660;
        </h2>
        <div id="empty-topics" class="collapsible-content">
            <div class='empty-topics-list'>
"""
            for topic_result in empty_topics:
                topic = html_escape(str(topic_result.get('topic', 'Unknown')))
                html += f"<div>{topic}</div>\n"
            html += """
            </div>
        </div>
"""

        # Add errors if any
        errors = results.get('errors', [])
        if errors:
            html += "<h2>Errors</h2>\n<div class='error'>\n"
            for error in errors:
                html += f"<p>{html_escape(str(error))}</p>\n"
            html += "</div>\n"

        html += """
    </div>
</body>
</html>
"""
        return html
