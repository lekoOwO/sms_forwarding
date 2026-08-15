#include "sms_process.h"
#include "web_handlers.h"
#include "modem.h"
#include "push.h"

static bool isValidConcatMetadata(int partNumber, int totalParts) {
  return totalParts > 1 && totalParts <= MAX_CONCAT_PARTS &&
         partNumber > 0 && partNumber <= totalParts;
}

// Initialize the concatenated SMS buffer
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

// Find or create a concatenated SMS buffer slot
int findOrCreateConcatSlot(int refNumber, const char* sender, int totalParts) {
  if (totalParts < 2 || totalParts > MAX_CONCAT_PARTS) return -1;

  // Reuse an existing matching slot.
  for (int i = 0; i < MAX_CONCAT_MESSAGES; i++) {
    if (concatBuffer[i].inUse && 
        concatBuffer[i].refNumber == refNumber &&
        concatBuffer[i].sender.equals(sender)) {
      if (concatBuffer[i].totalParts != totalParts) return -1;
      return i;
    }
  }
  
  // Find an unused slot.
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

// Assemble the parts of a concatenated SMS
String assembleConcatSms(int slot) {
  if (slot < 0 || slot >= MAX_CONCAT_MESSAGES ||
      concatBuffer[slot].totalParts < 1 ||
      concatBuffer[slot].totalParts > MAX_CONCAT_PARTS) return "";

  String result = "";
  for (int i = 0; i < concatBuffer[slot].totalParts; i++) {
    if (concatBuffer[slot].parts[i].valid) {
      result += concatBuffer[slot].parts[i].text;
    } else {
      result += "[Missing part " + String(i + 1) + "]";
    }
  }
  return result;
}

// Clear a concatenated SMS slot
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

// Forward concatenated SMS messages after their parts time out
void checkConcatTimeout() {
  unsigned long now = millis();
  for (int i = 0; i < MAX_CONCAT_MESSAGES; i++) {
    if (concatBuffer[i].inUse) {
      if (now - concatBuffer[i].firstPartTime >= CONCAT_TIMEOUT_MS) {
        // Assemble the parts received so far.
        String fullText = assembleConcatSms(i);
        
        // Do not forward incomplete administrator messages externally.
        if (isAdmin(concatBuffer[i].sender.c_str())) {
          logCaptureLn(String("Incomplete administrator multipart SMS discarded"));
        } else {
          processSmsContent(concatBuffer[i].sender.c_str(),
                            fullText.c_str(),
                            concatBuffer[i].timestamp.c_str());
        }
        
        // Clear the slot.
        clearConcatSlot(i);
      }
    }
  }
}

// Check whether a string is valid hexadecimal PDU data
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

// Check whether the sender is in the phone number blacklist
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

// Check whether the sender is the administrator
bool isAdmin(const char* sender) {
  if (config.adminPhone.length() == 0) return false;

  String senderStr = normalizePhoneNumber(sender);
  String adminStr = normalizePhoneNumber(config.adminPhone.c_str());
  return senderStr.length() > 0 && adminStr.length() > 0 && senderStr.equals(adminStr);
}

// Process final SMS contents. SMS is notification data and never executes management commands.
void processSmsContent(const char* sender, const char* text, const char* timestamp) {
  // Ignore blacklisted senders.
  if (isInNumberBlackList(sender)) {
    return;
  }

  // Push the notification to all enabled channels.
  sendSMSToServer(sender, text, timestamp);
  // Send the notification by email.
  String subject = ""; subject+="SMS from ";subject+=sender;subject+=": ";subject+=text;
  String body = ""; body+="From: ";body+=sender;body+=", Time: ";body+=timestamp;body+=", Message: ";body+=text;
  sendEmailNotification(subject.c_str(), body.c_str());
}

static enum { CMT_IDLE, CMT_WAIT_PDU } cmtState = CMT_IDLE;
static unsigned long waitPduSince = 0;

void checkSerial1URC() {
  if (cmtState == CMT_WAIT_PDU && millis() - waitPduSince >= PDU_WAIT_TIMEOUT_MS) {
    logCaptureLn(String("Timed out waiting for PDU; returning to IDLE state"));
    cmtState = CMT_IDLE;
  }
}

// Called for each line by the modem dispatcher; returns true for an SMS URC or PDU line.
bool processModemLine(const String& line) {
  checkSerial1URC();
  if (line.length() == 0) return false;

  if (cmtState == CMT_IDLE) {
    // Detect the incoming SMS URC header.
    if (line.startsWith("+CMT:")) {
      cmtState = CMT_WAIT_PDU;
      waitPduSince = millis();
      return true;
    }
    return false;
  } else if (cmtState == CMT_WAIT_PDU) {
    // Treat a hexadecimal string as PDU data.
    if (isHexString(line)) {
      // Decode the PDU.
      int* concatInfo = pdu.getConcatInfo();
      concatInfo[0] = concatInfo[1] = concatInfo[2] = 0;
      if (!pdu.decodePDU(line.c_str(), line.length())) {
        logCaptureLn(String("❌ Failed to decode PDU"));
      } else {
        // Read concatenated SMS metadata.
        int refNumber = concatInfo[0];
        int partNumber = concatInfo[1];
        int totalParts = concatInfo[2];
        
        // Check whether this is a concatenated SMS.
        if (totalParts > 1 && !isValidConcatMetadata(partNumber, totalParts)) {
          logCaptureLn(String("❌ Invalid concatenated SMS metadata; message discarded"));
        } else if (totalParts > 1) {
          // This is one part of a concatenated SMS.
          // Find or create a buffer slot.
          int slot = findOrCreateConcatSlot(refNumber, pdu.getSender(), totalParts);

          if (slot < 0) {
            logCaptureLn(String("❌ Concatenated SMS buffer rejected an inconsistent or excess part"));
          } else {
            // Store the part; partNumber is one-based and the array is zero-based.
            int partIndex = partNumber - 1;
            if (!concatBuffer[slot].parts[partIndex].valid) {
              concatBuffer[slot].parts[partIndex].valid = true;
              concatBuffer[slot].parts[partIndex].text = String(pdu.getText());
              concatBuffer[slot].receivedParts++;
              
              // Save the timestamp from the first received part.
              if (concatBuffer[slot].receivedParts == 1) {
                concatBuffer[slot].timestamp = String(pdu.getTimeStamp());
              }
              
            }

            // Check whether all parts have arrived.
            if (concatBuffer[slot].receivedParts >= concatBuffer[slot].totalParts) {
              String fullText = assembleConcatSms(slot);
              processSmsContent(concatBuffer[slot].sender.c_str(),
                                fullText.c_str(),
                                concatBuffer[slot].timestamp.c_str());
              clearConcatSlot(slot);
            }
          }
        } else {
          // Process a single-part SMS immediately.
          processSmsContent(pdu.getSender(), pdu.getText(), pdu.getTimeStamp());
        }
      }
      
      // Return to the IDLE state.
      cmtState = CMT_IDLE;
    } 
    // Other content, such as OK or ERROR, also returns to IDLE.
    else {
      logCaptureLn(String("Received non-PDU data; returning to IDLE state"));
      cmtState = CMT_IDLE;
    }
    return true;
  }
  return false;
}
