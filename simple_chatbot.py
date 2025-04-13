import google.generativeai as genai
import json
import logging
from datetime import datetime
import os
from pathlib import Path
from dotenv import load_dotenv


from config import GEMINI_API_KEY, CHATBOT_SETTINGS, CHAT_HISTORY_DIR, KB_CONFIG
from langchain.memory import ConversationBufferMemory  # for LangChain's memory module
from langchain.prompts import PromptTemplate  # for LangChain's prompt module


# Configure logging
logger = logging.getLogger(__name__)
load_dotenv()  # To load environment variables from a .env file

class SecurityContextManager:
    def __init__(self):
        self.memory = ConversationBufferMemory(k=CHATBOT_SETTINGS['max_history'])
        self.kb = self._load_knowledge_base()
        
    def _load_knowledge_base(self):
        kb = {}
        for source, url in KB_CONFIG['sources'].items():
            try:
                kb[source] = self._fetch_kb_data(url)
            except Exception as e:
                logger.error(f"Error loading {source} KB: {e}")
        return kb
    
    def get_relevant_context(self, query, vulnerability=None):
        context = []
        
        # Add relevant KB entries
        for source, data in self.kb.items():
            relevant_entries = self._search_kb(query, data)
            context.extend(relevant_entries)
        
        # Add conversation history
        history = self.memory.load_memory_variables({})
        context.append(history.get('history', ''))
        
        # Add vulnerability context if provided
        if vulnerability:
            context.append(json.dumps(vulnerability))
        
        return "\n\n".join(context)

class SimpleSecurityChatbot:
    def __init__(self):
        """Initialize the simple security chatbot"""
        try:
            api_key = os.getenv('GEMINI_API_KEY')
            if not api_key:
                raise ValueError("GEMINI_API_KEY not found in environment variables")
            
            genai.configure(api_key=api_key)
            
            # Try to list available models first
            try:
                available_models = genai.list_models()
                logger.info(f"Available models: {[m.name for m in available_models]}")
                
                # Try to use gemini-pro, fall back to other models if available
                try:
                    self.model = genai.GenerativeModel('gemini-pro')
                    self.gemini_available = True
                    logger.info("Using gemini-pro model")
                except Exception as e:
                    logger.warning(f"gemini-pro model not available: {e}")
                    # Try to find an alternative model
                    for model in available_models:
                        if 'gemini' in model.name.lower():
                            try:
                                self.model = genai.GenerativeModel(model.name)
                                self.gemini_available = True
                                logger.info(f"Using alternative model: {model.name}")
                                break
                            except Exception:
                                continue
                    
                    if not self.gemini_available:
                        logger.warning("No suitable Gemini models found")
                        self.gemini_available = False
            except Exception as e:
                logger.warning(f"Could not list models: {e}")
                self.gemini_available = False
            
            if self.gemini_available:
                self.chat = self.model.start_chat(history=[])
            else:
                logger.warning("Chatbot initialized without Gemini API")
        except Exception as e:
            logger.error(f"Error initializing chatbot: {e}")
            self.gemini_available = False
            raise

    def process_query(self, query, context=None):
        """Process a user query about security"""
        try:
            if not self.gemini_available:
                return "I'm sorry, but I'm currently unable to process your query due to API limitations. Please try again later or contact the administrator."
                
            # Create prompt with security context
            prompt = self._create_security_prompt(query, context)
            
            # Get response from Gemini
            response = self.chat.send_message(prompt)
            return response.text
        except Exception as e:
            logger.error(f"Error processing query: {e}")
            return f"I encountered an error: {str(e)}"

    def _create_security_prompt(self, query, context=None):
        """Create a security-focused prompt"""
        base_prompt = """
        You are a security expert assistant helping users understand and fix vulnerabilities.
        Provide clear, practical advice focusing on:
        - Vulnerability explanation
        - Risk assessment
        - Practical fix suggestions
        - Security best practices
        """
        
        if context:
            return f"{base_prompt}\nContext: {context}\nQuery: {query}"
        return f"{base_prompt}\nQuery: {query}"

    def get_fix_suggestion(self, vulnerability):
        """Get specific fix suggestions for a vulnerability"""
        prompt = f"""
        Provide a detailed fix for this security vulnerability:
        {vulnerability}
        
        Include:
        1. Step-by-step fix instructions
        2. Code examples (if applicable)
        3. Best practices to prevent similar issues
        """
        
        try:
            response = self.chat.send_message(prompt)
            return response.text
        except Exception as e:
            logger.error(f"Error getting fix suggestion: {e}")
            return "Unable to generate fix suggestion at the moment."

    def clear_context(self):
        """Clear the conversation context"""
        try:
            self.chat = self.model.start_chat(history=[])
            return True
        except Exception as e:
            logger.error(f"Error clearing context: {e}")
            return False

class VulnerabilityChatbot:
    def __init__(self):
        """Initialize the VulnerabilityChatbot with Gemini API."""
        try:
            logger.info("Initializing VulnerabilityChatbot")
            genai.configure(api_key=GEMINI_API_KEY)
            self.model = genai.GenerativeModel('gemini-pro')
            self.context_manager = SecurityContextManager()
            self.chat = self.model.start_chat(history=[])
            
            # Ensure chat history directory exists
            Path(CHAT_HISTORY_DIR).mkdir(parents=True, exist_ok=True)
        except Exception as e:
            logger.error(f"Error initializing VulnerabilityChatbot: {e}")
            raise
        
    def process_query(self, query, vulnerability=None):
        """Process a user query about vulnerabilities."""
        try:
            logger.info(f"Processing query: {query[:50]}...")
            
            # Get relevant context
            context = self.context_manager.get_relevant_context(query, vulnerability)
            
            # Create enhanced prompt
            prompt = self._create_enhanced_prompt(query, context)
            
            # Get response from Gemini
            response = self.chat.send_message(prompt)
            
            # Update memory
            self.context_manager.memory.save_context(
                {"input": query},
                {"output": response.text}
            )
            
            return response.text
        except Exception as e:
            logger.error(f"Error processing query: {e}")
            return "I'm sorry, I encountered an error processing your query. Please try again or check the logs for details."
    
    def _create_enhanced_prompt(self, query, context):
        """Create a prompt with context for the chatbot."""
        try:
            return PromptTemplate(
                input_variables=["context", "query"],
                template="""
                You are a security expert assistant. Use the following context to provide
                a detailed and helpful response:
                
                Context:
                {context}
                
                User Query: {query}
                
                Provide a clear, actionable response with:
                1. Direct answer to the query
                2. Technical details if relevant
                3. Code examples if applicable
                4. Best practices and recommendations
                5. References to relevant security standards
                """
            ).format(context=context, query=query)
        except Exception as e:
            logger.error(f"Error creating prompt: {e}")
            return f"User Query: {query}\n\nPlease provide a helpful response about this security question."
    
    def save_conversation(self, output_dir=CHAT_HISTORY_DIR):
        """Save the conversation history to a file."""
        try:
            logger.info("Saving conversation history")
            # Ensure the directory exists
            Path(output_dir).mkdir(parents=True, exist_ok=True)
            
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"chat_history_{timestamp}.json"
            filepath = Path(output_dir) / filename
            
            with open(filepath, 'w') as f:
                json.dump(self.context_manager.memory.load_memory_variables({})['history'], f, indent=2)
            
            logger.info(f"Conversation saved to {filepath}")
            return str(filepath)
        except Exception as e:
            logger.error(f"Error saving conversation: {e}")
            return None
    
    def clear_context(self):
        """Clear the conversation context."""
        try:
            logger.info("Clearing conversation context")
            self.context_manager.memory.clear()
            self.chat = self.model.start_chat(history=[])
            return True
        except Exception as e:
            logger.error(f"Error clearing context: {e}")
            return False
    
    def get_vulnerability_details(self, vulnerability_id):
        """Get detailed information about a specific vulnerability."""
        try:
            logger.info(f"Getting details for vulnerability ID: {vulnerability_id}")
            prompt = f"""
            Provide detailed information about vulnerability ID: {vulnerability_id}
            
            Include:
            1. Description of the vulnerability
            2. Potential impact
            3. Common attack vectors
            4. Best practices for prevention
            5. Example code showing the vulnerability and its fix
            """
            
            response = self.chat.send_message(prompt)
            return response.text
        except Exception as e:
            logger.error(f"Error getting vulnerability details: {e}")
            return f"Error retrieving details for vulnerability ID: {vulnerability_id}. Please check the logs for details."
    
    def get_security_best_practices(self, topic):
        """Get security best practices for a specific topic."""
        try:
            logger.info(f"Getting security best practices for topic: {topic}")
            prompt = f"""
            Provide comprehensive security best practices for: {topic}
            
            Include:
            1. Key principles
            2. Common pitfalls to avoid
            3. Implementation guidelines
            4. Code examples
            5. Additional resources
            """
            
            response = self.chat.send_message(prompt)
            return response.text
        except Exception as e:
            logger.error(f"Error getting security best practices: {e}")
            return f"Error retrieving security best practices for: {topic}. Please check the logs for details."
            
    def analyze_vulnerability(self, vulnerability):
        """Analyze a vulnerability and provide insights."""
        try:
            logger.info("Analyzing vulnerability")
            prompt = f"""
            Analyze this vulnerability and provide insights:
            {json.dumps(vulnerability, indent=2)}
            
            Include:
            1. Risk assessment
            2. Potential impact on the system
            3. Recommended priority for fixing
            4. Similar known vulnerabilities
            5. Industry-specific considerations
            """
            
            response = self.chat.send_message(prompt)
            return response.text
        except Exception as e:
            logger.error(f"Error analyzing vulnerability: {e}")
            return "Error analyzing vulnerability. Please check the logs for details."

def main():
    """Main function to run the chatbot interface."""
    try:
        logger.info("Starting VulnerabilityChatbot CLI")
        chatbot = VulnerabilityChatbot()
        
        print("Welcome to the Vulnerability Assistant!")
        print("Type 'exit' to quit, 'clear' to clear context, or 'save' to save conversation.")
        
        while True:
            query = input("\nYour question: ").strip()
            
            if query.lower() == 'exit':
                break
            elif query.lower() == 'clear':
                if chatbot.clear_context():
                    print("Context cleared!")
                else:
                    print("Error clearing context. Please check the logs.")
                continue
            elif query.lower() == 'save':
                filepath = chatbot.save_conversation()
                if filepath:
                    print(f"Conversation saved to: {filepath}")
                else:
                    print("Error saving conversation. Please check the logs.")
                continue
            
            response = chatbot.process_query(query)
            print("\nAssistant:", response)
    except Exception as e:
        logger.error(f"Error in main function: {e}")
        print("An error occurred. Please check the logs for details.")

if __name__ == "__main__":
    main() 