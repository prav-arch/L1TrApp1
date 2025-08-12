#!/usr/bin/env python3
"""
Mistral AI LLM Service for generating network troubleshooting recommendations
"""

import os
import json
import subprocess
from typing import Generator, Dict, Any

class MistralLLMService:
    def __init__(self):
        self.model_path = "/tmp/llm_models"
        self.model_file = "mistral-7b-instruct-v0.2.Q4_K_M.gguf"
        self.full_model_path = os.path.join(self.model_path, self.model_file)
        
    def is_model_available(self) -> bool:
        """Check if Mistral model is available"""
        return os.path.exists(self.full_model_path)
    
    def generate_troubleshooting_prompt(self, anomaly: Dict[str, Any]) -> str:
        """Generate a detailed prompt for troubleshooting recommendations"""
        context_data = json.loads(anomaly.get('context_data', '{}'))
        
        prompt = f"""You are an expert L1 network troubleshooting engineer specializing in 5G telecommunications systems. 

ANOMALY DETAILS:
- Type: {anomaly.get('anomaly_type', 'Unknown')}
- Severity: {anomaly.get('severity', 'Unknown')}
- Description: {anomaly.get('description', 'No description')}
- Confidence: {anomaly.get('confidence_score', 0):.1%}
- Detection Algorithm: {anomaly.get('detection_algorithm', 'Unknown')}
- Source File: {anomaly.get('source_file', 'Unknown')}

NETWORK CONTEXT:
- Cell ID: {context_data.get('cell_id', 'Unknown')}
- Sector: {context_data.get('sector_id', 'Unknown')}
- Frequency Band: {context_data.get('frequency_band', 'Unknown')}
- Technology: {context_data.get('technology', '5G-NR')}
- Affected Users: {context_data.get('affected_users', 'Unknown')}

Please provide a comprehensive troubleshooting recommendation including:

1. ROOT CAUSE ANALYSIS: What likely caused this anomaly?
2. IMMEDIATE ACTIONS: Quick steps to mitigate the issue
3. DETAILED INVESTIGATION: Systematic approach to diagnose the problem
4. LONG-TERM RESOLUTION: How to prevent this anomaly in the future
5. MONITORING RECOMMENDATIONS: Key metrics to watch

Keep your response technical but clear, focusing on actionable steps that a network operations team can execute immediately."""

        return prompt
    
    def stream_recommendations(self, anomaly: Dict[str, Any]) -> Generator[str, None, None]:
        """Stream troubleshooting recommendations token by token"""
        prompt = self.generate_troubleshooting_prompt(anomaly)
        
        # Always show the prompt first
        yield f"🔍 **ANALYSIS PROMPT SENT TO LLM:**\n\n{prompt}\n\n" + "="*80 + "\n\n🤖 **LLM RESPONSE:**\n\n"
        
        if not self.is_model_available():
            yield f"⚠️ Mistral AI model not found at {self.full_model_path}. Using fallback recommendations...\n\n"
            yield self.generate_fallback_recommendation(anomaly)
            return
        
        try:
            # Commands for GGUF format Mistral models
            possible_commands = [
                # llama.cpp style commands
                ["./llama.cpp/main", "-m", self.full_model_path, "-p", prompt, "--interactive-first"],
                ["llama-cpp-python", "-m", self.full_model_path, "-p", prompt],
                # Alternative llamacpp implementations
                ["./main", "-m", self.full_model_path, "-p", prompt, "--interactive-first"],
                ["llamacpp", "-m", self.full_model_path, "-p", prompt],
                # Python-based implementations
                ["python3", "-c", f"import llama_cpp; llm = llama_cpp.Llama(model_path='{self.full_model_path}'); print(llm('{prompt}', max_tokens=512, stream=True))"]
            ]
            
            process = None
            
            for cmd in possible_commands:
                try:
                    # Try to run the command from the model directory
                    process = subprocess.Popen(
                        cmd,
                        cwd=self.model_path,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        bufsize=1,
                        universal_newlines=True
                    )
                    break
                except (FileNotFoundError, PermissionError):
                    continue
            
            if process is None:
                # Fallback to a simple text-based recommendation
                yield self.generate_fallback_recommendation(anomaly)
                return
            
            # Stream the output token by token
            if process.stdout:
                for line in iter(process.stdout.readline, ''):
                    if line.strip():
                        yield line.strip()
                
                process.wait()
                
                # Check for errors
                if process.returncode != 0 and process.stderr:
                    error_output = process.stderr.read()
                    yield f"Error running Mistral model: {error_output}"
                    yield self.generate_fallback_recommendation(anomaly)
                
        except Exception as e:
            yield f"Error generating recommendations: {str(e)}"
            yield self.generate_fallback_recommendation(anomaly)
    
    def generate_fallback_recommendation(self, anomaly: Dict[str, Any]) -> str:
        """Generate a fallback recommendation when LLM is unavailable"""
        anomaly_type = anomaly.get('anomaly_type', '')
        severity = anomaly.get('severity', '')
        
        recommendations = {
            'fronthaul_du_ru_communication_failure': {
                'root_cause': 'Fronthaul interface issues between DU and RU units',
                'immediate_actions': [
                    'Check physical cable connections and SFP modules',
                    'Verify IP connectivity between DU and RU',
                    'Restart affected network interfaces'
                ],
                'investigation': [
                    'Analyze interface error counters and statistics',
                    'Check for electromagnetic interference',
                    'Verify timing synchronization between units'
                ],
                'resolution': 'Replace faulty cables, update firmware, implement redundancy'
            },
            'ue_attach_failure': {
                'root_cause': 'UE registration and authentication issues',
                'immediate_actions': [
                    'Check UE context and bearer establishment',
                    'Verify authentication server connectivity',
                    'Review radio resource availability'
                ],
                'investigation': [
                    'Analyze UE capability information',
                    'Check for overload conditions',
                    'Review security configurations'
                ],
                'resolution': 'Optimize resource allocation, update security policies'
            },
            'signal_quality_degradation': {
                'root_cause': 'RF interference or coverage issues',
                'immediate_actions': [
                    'Check antenna alignment and cable integrity',
                    'Perform drive test in affected area',
                    'Adjust transmission power if necessary'
                ],
                'investigation': [
                    'Analyze RSRP, RSRQ, and SINR measurements',
                    'Check for interference sources',
                    'Review neighbor cell relationships'
                ],
                'resolution': 'Optimize antenna tilt, add new sites, implement interference mitigation'
            }
        }
        
        default_rec = {
            'root_cause': 'L1 network anomaly requiring investigation',
            'immediate_actions': [
                'Isolate affected network elements',
                'Check system logs and alarms',
                'Verify basic connectivity'
            ],
            'investigation': [
                'Perform detailed log analysis',
                'Check hardware status',
                'Review recent configuration changes'
            ],
            'resolution': 'Address root cause based on investigation findings'
        }
        
        rec = recommendations.get(anomaly_type, default_rec)
        
        response = f"""## TROUBLESHOOTING RECOMMENDATIONS

**SEVERITY:** {severity.upper()}

### 1. ROOT CAUSE ANALYSIS
{rec['root_cause']}

### 2. IMMEDIATE ACTIONS
"""
        for action in rec['immediate_actions']:
            response += f"• {action}\n"
        
        response += "\n### 3. DETAILED INVESTIGATION\n"
        for step in rec['investigation']:
            response += f"• {step}\n"
        
        response += f"\n### 4. LONG-TERM RESOLUTION\n• {rec['resolution']}\n"
        
        response += """
### 5. MONITORING RECOMMENDATIONS
• Set up proactive monitoring for similar patterns
• Implement automated alerting for threshold breaches  
• Schedule regular preventive maintenance checks
• Review and update troubleshooting procedures

**Note:** This is a template recommendation. For detailed analysis, please ensure the Mistral AI model is properly configured at /tmp/llm_models."""
        
        return response

# Global service instance
llm_service = MistralLLMService()

def main():
    """Main function for command line execution"""
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python llm_service.py <anomaly_json>")
        sys.exit(1)
    
    try:
        anomaly_json = sys.argv[1]
        anomaly = json.loads(anomaly_json)
        
        # Stream recommendations token by token
        for token in llm_service.stream_recommendations(anomaly):
            print(token, end='', flush=True)
            
    except Exception as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()