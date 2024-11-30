document.addEventListener("DOMContentLoaded", () => {
  const authForm = document.getElementById("auth-form");
  const authTitle = document.getElementById("auth-title");
  const toggleAuth = document.getElementById("toggle-auth");
  const mainSection = document.getElementById("main-section");
  const authSection = document.getElementById("auth-section");
  const logoutLink = document.getElementById("logout-link");
  const receivedFilesSection = document.getElementById("received-files");

  let isLogin = true;
  let server_url = "http://127.0.0.1:5000";
  const socket = io("http://127.0.0.1:5000");

  // Toggle between Login and Signup
  toggleAuth.addEventListener("click", (e) => {
    e.preventDefault();
    isLogin = !isLogin;
    authTitle.textContent = isLogin ? "Login" : "Sign Up";
    toggleAuth.innerHTML = isLogin
      ? `Don't have an account? <a href="#" id="switch-to-signup">Sign up here</a>`
      : `Already have an account? <a href="#" id="switch-to-login">Login here</a>`;
    document.getElementById("auth-submit").textContent = isLogin
      ? "Login"
      : "Sign Up";
  });

  // Handle Login/Signup
  authForm.addEventListener("submit", async (e) => {
    e.preventDefault();

    const username = document.getElementById("username").value;
    const password = document.getElementById("password").value;

    const endpoint = isLogin ? "/login" : "/signup";
    const response = await fetch(`${server_url}${endpoint}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    });

    const result = await response.json();
    alert(result.message);

    if (response.ok && isLogin) {
      // If login is successful
      localStorage.setItem("username", username);
      authSection.classList.add("hidden");
      mainSection.classList.remove("hidden");
      logoutLink.classList.remove("hidden");
      fetchRequests();
    } else if (!isLogin && response.ok) {
      // If signup is successful
      alert("Sign up successful! Please log in.");
      isLogin = true;
      authTitle.textContent = "Login";
      toggleAuth.innerHTML = `Don't have an account? <a href="#" id="switch-to-signup">Sign up here</a>`;
      document.getElementById("auth-submit").textContent = "Login";
    }
  });

  // Handle Logout
  logoutLink.addEventListener("click", () => {
    localStorage.removeItem("username");
    authSection.classList.remove("hidden");
    mainSection.classList.add("hidden");
    logoutLink.classList.add("hidden");
  });

  function joinRoom() {
    const username = localStorage.getItem("username");
    if (username) {
      socket.emit("join", { username });
    }
  }

  socket.on("user_joined", (data) => {
    const { username } = data;
    alert(`${username} joined.`);
    // console.log(data.message); // Should log "Connection successful!"
  });

  socket.on("request_accepted", (data) => {
    const { sender, filename, msg } = data;
    alert(`${sender} accepted request`);
    // console.log(data.message); // Should log "Connection successful!"
  });

  socket.on("request_rejected", (data) => {
    const { sender, filename, msg } = data;
    alert(`${sender} rejected request`);

    // console.log(data.message); // Should log "Connection successful!"
  });

  socket.on("request_received", (data) => {
    const requestEmptyLabel = document.getElementById("request-empty-label");
    if (requestEmptyLabel) {
      requestEmptyLabel.classList.add("hidden");
    }

    const { sender, filename, encryptedContent } = data;

    // Find or create the request list container
    const requestList = document.getElementById("request-list");
    if (!requestList) {
      console.error("Request list container not found.");
      return;
    }

    // Create a list item for the request
    const listItem = document.createElement("li");
    listItem.className = "request-item";

    // Add sender and filename information
    const requestInfo = document.createElement("p");
    requestInfo.textContent = `File: ${filename} from ${sender}`;
    listItem.appendChild(requestInfo);

    // Create the "Allow" button
    const allowButton = document.createElement("button");
    allowButton.textContent = "Allow";
    allowButton.className = "allow-button";
    allowButton.onclick = () =>
      handleAllowRequest(sender, filename, encryptedContent, listItem);

    // Create the "Reject" button
    const rejectButton = document.createElement("button");
    rejectButton.textContent = "Reject";
    rejectButton.className = "reject-button";
    rejectButton.onclick = () =>
      handleRejectRequest(sender, filename, listItem);

    // Add buttons to the list item
    listItem.appendChild(allowButton);
    listItem.appendChild(rejectButton);

    // Add the list item to the request list
    requestList.appendChild(listItem);
  });

  // Function to handle "Allow" request
  function handleAllowRequest(sender, filename, encryptedContent, listText) {
    console.log(`Allowing request from ${sender} for file ${filename}`);
    const listItem = document.createElement("li");
    listItem.textContent = `${filename} from ${sender}`;

    // Add Download Encrypted File button
    const downloadEncryptedButton = document.createElement("button");
    downloadEncryptedButton.textContent = "Download Encrypted File";
    downloadEncryptedButton.onclick = () => {
      // Create a Blob from the encrypted content
      const blob = new Blob([encryptedContent], { type: "text/plain" });
      const link = document.createElement("a");
      link.href = URL.createObjectURL(blob);
      link.download = filename; // Set the download file name
      link.click(); // Trigger the download
    };

    // Add Download Decrypted File button
    const downloadDecryptedButton = document.createElement("button");
    downloadDecryptedButton.textContent = "Download Decrypted File";
    downloadDecryptedButton.onclick = async () => {
      //   const secretKey = "my-secret-key"; // Same key used for encryption
      //   const bytes = CryptoJS.AES.decrypt(encryptedContent, secretKey);
      //   const decryptedContent = atob(bytes.toString(CryptoJS.enc.Utf8)); // Decode Base64

      const response = await fetch("http://127.0.0.1:5000/decrypt", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ encryptedContent: encryptedContent }), // Pass encrypted content
      });

      const result = await response.json();
      //   const decryptedContent = result.decryptedContent;
      const decryptedContent = atob(result.decryptedContent);

      // Create a Blob from the decrypted content
      const blob = new Blob([decryptedContent], { type: "text/plain" });
      const link = document.createElement("a");
      link.href = URL.createObjectURL(blob);
      link.download = filename; // Set the download file name
      link.click(); // Trigger the download

      socket.emit("accept_request", {
        sender: localStorage.getItem("username"),
        receiver: sender,
        filename: filename,
      });
    };

    // Append buttons to the list item
    listItem.appendChild(downloadEncryptedButton);
    listItem.appendChild(downloadDecryptedButton);
    receivedFilesSection.appendChild(listItem);

    listText.innerHTML = `Request from ${sender} allowed and ${filename} is added to Received Files section.`;
  }

  // Function to handle "Reject" request
  function handleRejectRequest(sender, filename, listText) {
    console.log(`Rejecting request from ${sender} for file ${filename}`);
    listText.innerHTML = `Request from ${sender} rejected for file : ${filename}.`;
    socket.emit("reject_request", {
      sender: localStorage.getItem("username"),
      receiver: sender,
      filename: filename,
    });
  }

  // Decrypt function (simplified for client-side)
  function decryptFile(encryptedData) {
    // Use a decryption function matching the server-side logic
    return atob(encryptedData); // Simplified example for clarity
  }

  // File Upload
  document
    .getElementById("upload-button")
    .addEventListener("click", async (e) => {
      e.preventDefault();

      const fileInput = document.getElementById("file-input");
      const receiver = document.getElementById("receiver-name");
      //   const receiver = prompt("Enter receiver's username:");
      console.log("receiver is: ", receiver);
      if (!receiver || receiver.value.trim() === "") {
        alert("Receiver's username is required.");
        return;
      }

      if (fileInput.files.length === 0) {
        alert("Please select a file to upload.");
        return;
      }

      const file = fileInput.files[0];
      const reader = new FileReader();

      reader.onload = async () => {
        const fileContent = reader.result.split(",")[1]; // Base64 encoded content

        // Encrypt the content using AES
        // const secretKey = "my-secret-key"; // Replace with a securely shared key
        // const encryptedContent = CryptoJS.AES.encrypt(
        //   fileContent,
        //   secretKey
        // ).toString();

        // Send file content to Flask for encryption
        const response = await fetch("http://127.0.0.1:5000/encrypt", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ content: fileContent }),
        });

        const result = await response.json();
        const encryptedContent = result.encryptedContent;

        // Send the encrypted file and metadata to the server
        socket.emit("send_request", {
          sender: localStorage.getItem("username"),
          receiver: receiver.value,
          filename: file.name,
          encryptedContent: encryptedContent, // Encrypted content
        });

        alert(`File sent to ${receiver.value}!`);
      };

      reader.readAsDataURL(file); // Read file as Base64
    });

  // On login, join the shared room
  if (localStorage.getItem("username")) {
    joinRoom();
  }

  // Check if user is already logged in
  if (localStorage.getItem("username")) {
    authSection.classList.add("hidden");
    mainSection.classList.remove("hidden");
    logoutLink.classList.remove("hidden");
  }
});
