# Secure Client-Server Connection Using a Distributed Double DES (D-DDES)

SNS Assignment 1

## Prerequisites
Before running the program, ensure that you have the following installed:
- Python 3.6 or later: Download and install Python from python.org.
- Required Python Packages - pycryptodome
 
To install pycryptodome, use the following command:

```bash
pip install pycryptodome
```

## How to Run the Program

Follow these steps to run the server and client programs:

### Start the Server:

- Open a terminal or command prompt.
- Navigate to the directory where server.py is located.
- Run the following command to start the server:

```python
python3 server.py
```

### Run the Client:

- Open another terminal or command prompt.
- Navigate to the directory where client.py is located.
- Run the following command to start the client:

```python
python3 client.py
```

### Features
- The client can send data multiple times, and the server will compute the average of the data sent by each client and return the result to the respective client securely .
