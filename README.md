# Malicious URL Detector

A web application that uses a trained LSTM model to detect malicious URLs with 96% accuracy.

## Features

- Modern, responsive web interface
- Real-time URL analysis
- Confidence score display
- Easy to use and deploy

## Prerequisites

- Python 3.8 or higher
- pip (Python package manager)

## Installation

1. Clone this repository:
```bash
git clone <repository-url>
cd malicious-url-detector
```

2. Create a virtual environment (recommended):
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install the required packages:
```bash
pip install -r requirements.txt
```

## Usage

1. Make sure your trained LSTM model file (`LSTM.h5`) is in the root directory of the project.

2. Run the Flask application:
```bash
python app.py
```

3. Open your web browser and navigate to:
```
http://localhost:5000
```

4. Enter a URL in the input field and click "Check URL" to analyze it.

## How it Works

The application uses a pre-trained LSTM model to analyze URLs. When a URL is submitted:
1. The URL is preprocessed (lowercase, remove protocol, etc.)
2. Characters are converted to ASCII values
3. The input is padded/truncated to a fixed length
4. The model makes a prediction
5. Results are displayed with confidence scores

## Model Information

- Model Type: LSTM
- Accuracy: 96%
- Input: URL string
- Output: Probability of being malicious (0-1)

## Contributing

Feel free to submit issues and enhancement requests! 
