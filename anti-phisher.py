import tkinter as tk
from tkinter import messagebox, Frame
import joblib
import re
import threading

class PhishingDetector:
    def __init__(self, root):
        self.root = root
        self.root.title("Phishing Email Analyzer")
        self.root.geometry("800x700")
        self.root.configure(bg="#1A1A1A")

        # Initialize loading screen
        self.loading_label = tk.Label(root, text="Loading ML Model...",
                                       font=("Consolas", 16), bg="#1A1A1A", fg="#FF0000")
        self.loading_label.pack(expand=True)

        # Initialize variables
        self.model = None
        self.tfidf_vectorizer = None
        self.model_status_indicator = None

        # Start loading ML model in the background
        threading.Thread(target=self.load_ml_model, daemon=True).start()

    def load_ml_model(self):
        # Load your machine learning model and vectorizer here
        # Example:
        # self.model = joblib.load('model_path.pkl')
        # self.tfidf_vectorizer = joblib.load('vectorizer_path.pkl')

        # Simulate loading delay
        import time
        time.sleep(3)  # Simulating loading time
        self.model = 'Your ML Model'  # Replace with actual model
        self.tfidf_vectorizer = 'Your TF-IDF Vectorizer'  # Replace with actual vectorizer

        # After loading, set up the main interface
        self.setup_main_interface()

    def setup_main_interface(self):
        # Remove loading label
        self.loading_label.destroy()

        # Main container
        self.main_frame = Frame(self.root, bg="#1A1A1A")
        self.main_frame.pack(expand=True, fill="both", padx=20, pady=20)

        # Title
        title = tk.Label(self.main_frame, text="PHISHING ANALYZER",
                         font=("Consolas", 24, "bold"), bg="#1A1A1A", fg="#FF0000")
        title.pack(pady=(0, 20))

        # Input section
        input_frame = Frame(self.main_frame, bg="#2D2D2D")
        input_frame.pack(fill="x", pady=(0, 20))

        input_label = tk.Label(input_frame, text="MESSAGE CONTENT",
                                font=("Consolas", 11), bg="#2D2D2D", fg="#888888")
        input_label.pack(pady=(15, 5), padx=15, anchor="w")

        self.text_input = tk.Text(input_frame, height=8,
                                   font=("Consolas", 12), bg="#333333", fg="#FFFFFF",
                                   insertbackground="#FF0000", bd=0)
        self.text_input.pack(fill="x", expand=True, padx=15, pady=(0, 15))

        # Analyze button
        self.analyze_button = tk.Button(input_frame, text="ANALYZE",
                                        command=self.validate_and_analyze,
                                        font=("Consolas", 12, "bold"),
                                        bg="#FF0000", fg="#FFFFFF",
                                        activebackground="#CC0000",
                                        activeforeground="#FFFFFF",
                                        relief="flat",
                                        padx=30, pady=8)
        self.analyze_button.pack(pady=(0, 15))

        # Results section
        self.results_frame = Frame(self.main_frame, bg="#1A1A1A")
        self.results_frame.pack(fill="both", expand=True)

        # Phishing detection message
        self.phishing_message_label = tk.Label(self.results_frame, text="Waiting for analysis...",
                                                font=("Consolas", 12), bg="#1A1A1A", fg="#FFFFFF")
        self.phishing_message_label.pack(anchor="w", pady=(10, 0))

        # Confidence score card
        self.confidence_value = self.create_card(self.results_frame,
                                                 "CONFIDENCE SCORE", "--")

        # Status section for ML model
        self.create_model_status_section()

        # Patterns card with custom styling for multiple lines
        patterns_card = Frame(self.results_frame, bg="#2D2D2D", padx=15, pady=15)
        patterns_card.pack(fill="x", padx=10, pady=5)

        patterns_title = tk.Label(patterns_card, text="DETECTED PATTERNS",
                                  font=("Consolas", 11), bg="#2D2D2D", fg="#888888")
        patterns_title.pack(anchor="w")

        self.patterns_value = tk.Label(patterns_card, text="Waiting for analysis...",
                                       font=("Consolas", 12), bg="#2D2D2D", fg="#FFFFFF",
                                       justify="left", wraplength=700)
        self.patterns_value.pack(anchor="w", pady=(10, 0))

        # Additional analysis results section
        self.additional_results_frame = Frame(self.results_frame, bg="#2D2D2D", padx=15, pady=15)
        self.additional_results_frame.pack(fill="x", padx=10, pady=5)

        additional_title = tk.Label(self.additional_results_frame, text="ADDITIONAL ANALYSIS RESULTS",
                                     font=("Consolas", 11), bg="#2D2D2D", fg="#888888")
        additional_title.pack(anchor="w")

        self.additional_results_value = tk.Text(self.additional_results_frame, height=6, width=60,
                                                 font=("Consolas", 12), bg="#333333", fg="#FFFFFF",
                                                 wrap="word", bd=0)
        self.additional_results_value.pack(anchor="w", pady=(10, 0))
        self.additional_results_value.config(state=tk.DISABLED)  # Initially disabled

    def create_model_status_section(self):
        """Create a compact status section for the machine learning model."""
        status_frame = Frame(self.results_frame, bg="#2D2D2D", padx=15, pady=15)
        status_frame.pack(fill="x", padx=10, pady=5, anchor="w")  # Align left

        title_label = tk.Label(status_frame, text="MODEL STATUS",
                                font=("Consolas", 11), bg="#2D2D2D", fg="#888888")
        title_label.pack(anchor="w")

        # Light Indicator
        self.model_status_indicator = tk.Canvas(status_frame, width=15, height=15, bg="#1A1A1A", highlightthickness=0)
        self.model_status_indicator.pack(side="left", padx=(0, 10))
        self.update_model_status_indicator(True)  # Assume model is loaded correctly

        self.model_status_value = tk.Label(status_frame, text="Model Loaded Successfully",
                                             font=("Consolas", 12), bg="#2D2D2D", fg="#FFFFFF")
        self.model_status_value.pack(anchor="w", pady=(5, 0))

        # Additional details
        self.model_details = tk.Label(status_frame, text="Model Type: Random Forest\n" +
                                       "Vectorizer Type: TF-IDF\n" +
                                       "Last Updated: 2024-10-26\n" +
                                       "Training Accuracy: 95%",
                                       font=("Consolas", 11), bg="#2D2D2D", fg="#FFFFFF")
        self.model_details.pack(anchor="w", pady=(5, 0))

    def update_model_status_indicator(self, is_running):
        """Update the model status indicator light."""
        color = "green" if is_running else "red"
        self.model_status_indicator.create_oval(2, 2, 13, 13, fill=color, outline=color)

    def validate_and_analyze(self):
        text = self.text_input.get("1.0", tk.END).strip()

        if not text:
            messagebox.showerror("Error", "Please enter some text to analyze.")
            return

        if not self.is_valid_input(text):
            messagebox.showerror("Error", "Please enter valid email content or message.\n\n" +
                                 "Valid content should include:\n" +
                                 "- Email messages\n" +
                                 "- URLs/links\n" +
                                 "- Text content\n\n" +
                                 "Please avoid special characters or code snippets.")
            return

        self.analyze_text()

    def is_valid_input(self, text):
        if len(text) < 10:
            return False

        email_pattern = r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}'
        url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'

        has_email = bool(re.search(email_pattern, text))
        has_url = bool(re.search(url_pattern, text))
        is_text = bool(re.search(r'[A-Za-z\s]{10,}', text))

        has_script = '<script' in text.lower() or 'javascript:' in text.lower()
        has_sql = 'select' in text.lower() and 'from' in text.lower()

        return (has_email or has_url or is_text) and not (has_script or has_sql)

    def analyze_text(self):
        # Here goes the model prediction logic
        # For demonstration, we'll mock the prediction and probabilities
        prediction = 'Phishing'  # or 'Legitimate'
        probabilities = [0.15, 0.85]  # Mocked probabilities for Legitimate and Phishing

        # Update UI based on prediction
        self.update_phishing_message(prediction, probabilities)

    def update_phishing_message(self, prediction, probabilities):
        if prediction == 'Phishing':
            self.phishing_message_label.config(text="Phishing Detected!", fg="#FF0000")
            self.confidence_value.config(text=f"Confidence Score: {probabilities[1] * 100:.2f}%")
            self.patterns_value.config(text="Detected Patterns: Suspicious links, Unusual sender")
            additional_info = (
                "Analysis Result: Potential phishing email.\n\n"
                "Recommendations:\n"
                "- Do not click on any links or download attachments.\n"
                "- Report the email to your email provider."
            )
        else:
            self.phishing_message_label.config(text="Legitimate Email.", fg="#00FF00")
            self.confidence_value.config(text=f"Confidence Score: {probabilities[0] * 100:.2f}%")
            self.patterns_value.config(text="Detected Patterns: None")
            additional_info = (
                "Analysis Result: Legitimate email.\n\n"
                "Recommendations:\n"
                "- You can proceed with caution.\n"
                "- Always verify the sender's address."
            )

        # Update additional results with a simulated delay
        self.update_additional_results(additional_info)

    def update_additional_results(self, additional_info):
        self.additional_results_value.config(state=tk.NORMAL)
        self.additional_results_value.delete("1.0", tk.END)
        self.additional_results_value.insert(tk.END, additional_info)
        self.additional_results_value.config(state=tk.DISABLED)

    def create_card(self, parent, title, value):
        """Create a card-like display for the results."""
        card = Frame(parent, bg="#2D2D2D", padx=15, pady=15)
        card.pack(fill="x", padx=10, pady=5)

        title_label = tk.Label(card, text=title,
                                font=("Consolas", 11), bg="#2D2D2D", fg="#888888")
        title_label.pack(anchor="w")

        value_label = tk.Label(card, text=value,
                                font=("Consolas", 16), bg="#2D2D2D", fg="#FFFFFF")
        value_label.pack(anchor="w", pady=(10, 0))

        return value_label

if __name__ == "__main__":
    root = tk.Tk()
    app = PhishingDetector(root)
    root.mainloop()
