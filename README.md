### README: How to Use the E2EE System

---

### **Overview**
This project implements an End-to-End Encrypted (E2EE) communication system with registration, key exchange, message encryption, and reconnection functionalities. The system uses a server and multiple client instances to simulate secure communication.

---

### **Requirements**
1. **Python 3.8+**
2. **Required Libraries** (Install via pip if not already installed):
   - `cryptography`
   - `json`
   - `socket`

To install dependencies, run:
```bash
pip install cryptography
```

---

### **Files**
- **`server.py`**: Manages client registration, key exchanges, and message storage.
- **`client.py`**: Implements client-side logic for registration, encryption, and message handling.
- **`run.bat`**: A batch file to automate starting the server and two client terminals.

---

### **Running the System**
1. Double-click the `run.bat` file. This will:
   - Open a terminal for the **server** (`server.py`).
   - Open two separate terminals for **clients** (`client.py`) with predefined client IDs (`+111111111` and `+222222222`).
2. Follow the prompts in each client terminal to perform actions.

---

### **Available Commands**
#### In the **Client Terminal**, use the following commands:

| Command                          | Description                                              |
|----------------------------------|----------------------------------------------------------|
| `register` / `r`                 | Begin the registration process (if not already registered). |
| `fetch_keys <id>` / `f <id>`     | Retrieve encryption keys for the specified client ID.    |
| `send <id> <msg>` / `s <id> <msg>` | Send a message to the specified client ID.              |
| `receive` / `recv` / `r`         | Retrieve and decrypt incoming messages.                 |
| `quit` / `exit` / `q` / `e`      | Exit the program gracefully.                            |

#### Examples:
- To register a client:
  ```
  > register
  ```
- To fetch keys for another client:
  ```
  > fetch_keys +222222222
  ```
- To send a message to another client:
  ```
  > send +222222222 Hello, how are you?
  ```
- To receive messages:
  ```
  > recv
  ```

---

### **Details**
1. **Server**: Runs a centralized hub for managing client registrations and message storage. It also generates and validates challenges during reconnection.
2. **Client**: Handles secure communication using key exchanges and encryption mechanisms such as AES-GCM.

---

### **Notes**
- Ensure you have a stable network connection between the server and clients.
- If running locally, make sure all terminals are on the same machine and ports are not blocked.
- For reconnection, use the client's **registered phone number** as the `client_id`. 

Enjoy secure communication!