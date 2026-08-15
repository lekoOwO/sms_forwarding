#include "sms_process.h"
#include "web_handlers.h"
#include "modem.h"
#include "push.h"

static bool isValidConcatMetadata(int partNumber, int totalParts) {
  return totalParts > 1 && totalParts <= MAX_CONCAT_PARTS &&
         partNumber > 0 && partNumber <= totalParts;
}

// 初始化长短信缓存
void initConcatBuffer() {
  for (int i = 0; i < MAX_CONCAT_MESSAGES; i++) {
    concatBuffer[i].inUse = false;
    concatBuffer[i].receivedParts = 0;
    for (int j = 0; j < MAX_CONCAT_PARTS; j++) {
      concatBuffer[i].parts[j].valid = false;
      concatBuffer[i].parts[j].text = "";
    }
  }
}

// 查找或创建长短信缓存槽位
int findOrCreateConcatSlot(int refNumber, const char* sender, int totalParts) {
  if (totalParts < 2 || totalParts > MAX_CONCAT_PARTS) return -1;

  // 先查找是否已存在
  for (int i = 0; i < MAX_CONCAT_MESSAGES; i++) {
    if (concatBuffer[i].inUse && 
        concatBuffer[i].refNumber == refNumber &&
        concatBuffer[i].sender.equals(sender)) {
      if (concatBuffer[i].totalParts != totalParts) return -1;
      return i;
    }
  }
  
  // 查找空闲槽位
  for (int i = 0; i < MAX_CONCAT_MESSAGES; i++) {
    if (!concatBuffer[i].inUse) {
      concatBuffer[i].inUse = true;
      concatBuffer[i].refNumber = refNumber;
      concatBuffer[i].sender = String(sender);
      concatBuffer[i].totalParts = totalParts;
      concatBuffer[i].receivedParts = 0;
      concatBuffer[i].firstPartTime = millis();
      for (int j = 0; j < MAX_CONCAT_PARTS; j++) {
        concatBuffer[i].parts[j].valid = false;
        concatBuffer[i].parts[j].text = "";
      }
      return i;
    }
  }
  
  return -1;
}

// 合并长短信各分段
String assembleConcatSms(int slot) {
  if (slot < 0 || slot >= MAX_CONCAT_MESSAGES ||
      concatBuffer[slot].totalParts < 1 ||
      concatBuffer[slot].totalParts > MAX_CONCAT_PARTS) return "";

  String result = "";
  for (int i = 0; i < concatBuffer[slot].totalParts; i++) {
    if (concatBuffer[slot].parts[i].valid) {
      result += concatBuffer[slot].parts[i].text;
    } else {
      result += "[缺失分段" + String(i + 1) + "]";
    }
  }
  return result;
}

// 清空长短信槽位
void clearConcatSlot(int slot) {
  concatBuffer[slot].inUse = false;
  concatBuffer[slot].receivedParts = 0;
  concatBuffer[slot].sender = "";
  concatBuffer[slot].timestamp = "";
  for (int j = 0; j < MAX_CONCAT_PARTS; j++) {
    concatBuffer[slot].parts[j].valid = false;
    concatBuffer[slot].parts[j].text = "";
  }
}

// 检查长短信超时并转发
void checkConcatTimeout() {
  unsigned long now = millis();
  for (int i = 0; i < MAX_CONCAT_MESSAGES; i++) {
    if (concatBuffer[i].inUse) {
      if (now - concatBuffer[i].firstPartTime >= CONCAT_TIMEOUT_MS) {
        // 合并已收到的分段
        String fullText = assembleConcatSms(i);
        
        // 不完整的管理员短信不得外部转发。
        if (isAdmin(concatBuffer[i].sender.c_str())) {
          logCaptureLn(String("管理员长短信不完整，已丢弃"));
        } else {
          processSmsContent(concatBuffer[i].sender.c_str(),
                            fullText.c_str(),
                            concatBuffer[i].timestamp.c_str());
        }
        
        // 清空槽位
        clearConcatSlot(i);
      }
    }
  }
}

// 检查字符串是否为有效的十六进制PDU数据
bool isHexString(const String& str) {
  if (str.length() == 0 || str.length() > MAX_PDU_LENGTH ||
      str.length() % 2 != 0) return false;
  for (unsigned int i = 0; i < str.length(); i++) {
    char c = str.charAt(i);
    if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f'))) {
      return false;
    }
  }
  return true;
}

static String normalizePhoneNumber(const char* phone) {
  String normalized = String(phone);
  normalized.trim();
  if (normalized.startsWith("+86")) normalized.remove(0, 3);
  return normalized;
}

// 检查发送者是否在号码黑名单中
bool isInNumberBlackList(const char* sender) {
  if (config.numberBlackList.length() == 0) return false;

  String normalizedSender = normalizePhoneNumber(sender);
  if (normalizedSender.length() == 0) return false;

  int listLen = (int)config.numberBlackList.length();

  int start = 0;
  while (start <= listLen) {
    int end = config.numberBlackList.indexOf('\n', start);
    if (end == -1) end = listLen;

    String line = config.numberBlackList.substring(start, end);
    line.trim();

    if (line.length() > 0 && normalizePhoneNumber(line.c_str()).equals(normalizedSender)) {
      return true;
    }

    start = end + 1;
  }

  return false;
}

// 检查发送者是否为管理员
bool isAdmin(const char* sender) {
  if (config.adminPhone.length() == 0) return false;

  String senderStr = normalizePhoneNumber(sender);
  String adminStr = normalizePhoneNumber(config.adminPhone.c_str());
  return senderStr.length() > 0 && adminStr.length() > 0 && senderStr.equals(adminStr);
}

// 处理最终的短信内容。SMS 一律视为通知数据，不执行管理命令。
void processSmsContent(const char* sender, const char* text, const char* timestamp) {
  // 检查是否在号码黑名单中
  if (isInNumberBlackList(sender)) {
    return;
  }

  // 发送通知http（推送到所有启用的通道）
  sendSMSToServer(sender, text, timestamp);
  // 发送通知邮件
  String subject = ""; subject+="短信";subject+=sender;subject+=",";subject+=text;
  String body = ""; body+="来自：";body+=sender;body+="，时间：";body+=timestamp;body+="，内容：";body+=text;
  sendEmailNotification(subject.c_str(), body.c_str());
}

static enum { CMT_IDLE, CMT_WAIT_PDU } cmtState = CMT_IDLE;
static unsigned long waitPduSince = 0;

void checkSerial1URC() {
  if (cmtState == CMT_WAIT_PDU && millis() - waitPduSince >= PDU_WAIT_TIMEOUT_MS) {
    logCaptureLn(String("等待PDU超时，返回IDLE状态"));
    cmtState = CMT_IDLE;
  }
}

// 由 modem dispatcher 逐行呼叫；回传 true 表示该行是 SMS URC/PDU。
bool processModemLine(const String& line) {
  checkSerial1URC();
  if (line.length() == 0) return false;

  if (cmtState == CMT_IDLE) {
    // 检测到短信上报URC头
    if (line.startsWith("+CMT:")) {
      cmtState = CMT_WAIT_PDU;
      waitPduSince = millis();
      return true;
    }
    return false;
  } else if (cmtState == CMT_WAIT_PDU) {
    // 如果是十六进制字符串，认为是PDU数据
    if (isHexString(line)) {
      // 解析PDU
      int* concatInfo = pdu.getConcatInfo();
      concatInfo[0] = concatInfo[1] = concatInfo[2] = 0;
      if (!pdu.decodePDU(line.c_str(), line.length())) {
        logCaptureLn(String("❌ PDU解析失败！"));
      } else {
        // 获取长短信信息
        int refNumber = concatInfo[0];
        int partNumber = concatInfo[1];
        int totalParts = concatInfo[2];
        
        // 判断是否为长短信
        if (totalParts > 1 && !isValidConcatMetadata(partNumber, totalParts)) {
          logCaptureLn(String("❌ 长短信分段信息无效，已丢弃"));
        } else if (totalParts > 1) {
          // 这是长短信的一部分
          // 查找或创建缓存槽位
          int slot = findOrCreateConcatSlot(refNumber, pdu.getSender(), totalParts);

          if (slot < 0) {
            logCaptureLn(String("❌ 长短信缓存拒绝了不一致或超额的分段"));
          } else {
            // 存储该分段（partNumber从1开始，数组从0开始）
            int partIndex = partNumber - 1;
            if (!concatBuffer[slot].parts[partIndex].valid) {
              concatBuffer[slot].parts[partIndex].valid = true;
              concatBuffer[slot].parts[partIndex].text = String(pdu.getText());
              concatBuffer[slot].receivedParts++;
              
              // 如果是第一个收到的分段，保存时间戳
              if (concatBuffer[slot].receivedParts == 1) {
                concatBuffer[slot].timestamp = String(pdu.getTimeStamp());
              }
              
            }

            // 检查是否已收齐所有分段
            if (concatBuffer[slot].receivedParts >= concatBuffer[slot].totalParts) {
              String fullText = assembleConcatSms(slot);
              processSmsContent(concatBuffer[slot].sender.c_str(),
                                fullText.c_str(),
                                concatBuffer[slot].timestamp.c_str());
              clearConcatSlot(slot);
            }
          }
        } else {
          // 普通短信，直接处理
          processSmsContent(pdu.getSender(), pdu.getText(), pdu.getTimeStamp());
        }
      }
      
      // 返回IDLE状态
      cmtState = CMT_IDLE;
    } 
    // 如果是其他内容（OK、ERROR等），也返回IDLE
    else {
      logCaptureLn(String("收到非PDU数据，返回IDLE状态"));
      cmtState = CMT_IDLE;
    }
    return true;
  }
  return false;
}
