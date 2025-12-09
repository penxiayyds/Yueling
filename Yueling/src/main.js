const { invoke } = window.__TAURI__.core;

// DOM元素
let protocolSelect;
let connectBtn;
let disconnectBtn;
let messagesDiv;
let messageInput;
let sendBtn;

window.addEventListener("DOMContentLoaded", () => {
  // 初始化DOM元素
  protocolSelect = document.querySelector("#protocol-select");
  connectBtn = document.querySelector("#connect-btn");
  disconnectBtn = document.querySelector("#disconnect-btn");
  messagesDiv = document.querySelector("#messages");
  messageInput = document.querySelector("#message-input");
  sendBtn = document.querySelector("#send-btn");

  // 添加事件监听器
  connectBtn.addEventListener("click", connectToServer);
  disconnectBtn.addEventListener("click", disconnect);
  sendBtn.addEventListener("click", sendMessage);
  messageInput.addEventListener("keypress", (e) => {
    if (e.key === "Enter") {
      sendMessage();
    }
  });
});

// 连接到服务器
async function connectToServer() {
  const protocol = protocolSelect.value;
  try {
    const result = await invoke("connect_to_server", {
      protocol: protocol
    });
    
    // 更新UI状态
    connectBtn.disabled = true;
    disconnectBtn.disabled = false;
    sendBtn.disabled = false;
    
    // 添加系统消息
    addMessage(`Connected via ${protocol}`, "server");
    
    console.log("Connection result:", result);
  } catch (error) {
    console.error("Connection error:", error);
    addMessage(`Connection failed: ${error}`, "server");
  }
}

// 断开连接
async function disconnect() {
  try {
    const result = await invoke("disconnect");
    
    // 更新UI状态
    connectBtn.disabled = false;
    disconnectBtn.disabled = true;
    sendBtn.disabled = true;
    
    // 添加系统消息
    addMessage("Disconnected", "server");
    
    console.log("Disconnect result:", result);
  } catch (error) {
    console.error("Disconnect error:", error);
    addMessage(`Disconnect failed: ${error}`, "server");
  }
}

// 发送消息
async function sendMessage() {
  const message = messageInput.value.trim();
  if (!message) return;
  
  try {
    const result = await invoke("send_message", {
      message: message
    });
    
    // 更新UI
    addMessage(message, "user");
    addMessage(result, "server");
    
    // 清空输入框
    messageInput.value = "";
    
    console.log("Send message result:", result);
  } catch (error) {
    console.error("Send message error:", error);
    addMessage(`Send failed: ${error}`, "server");
  }
}

// 添加消息到UI
function addMessage(text, sender) {
  const messageDiv = document.createElement("div");
  messageDiv.className = `message ${sender}`;
  messageDiv.textContent = text;
  messagesDiv.appendChild(messageDiv);
  
  // 滚动到底部
  messagesDiv.scrollTop = messagesDiv.scrollHeight;
}
