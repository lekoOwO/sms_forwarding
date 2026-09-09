static PduDecodeOutcome receive(int ref, int part, const char* text, const char* stamp="t") {
    return handle_decoded_pdu({"synthetic", text, stamp, {ref,part,3}}, true, true);
}
static void reset() {
    for(auto& slot:s_concat) clear_concat_slot(slot);
    s_concat_done={}; s_concat_done_next=0; outputs.clear(); blocked=false; now_us=0;
}
int main() {
    // 晚段補齊：原內容保留、只一則完整補充，完成重送不重發。
    reset(); receive(7,1,"A"); now_us=15LL*60*1000000+1; expire_concat_slots();
    assert(outputs.size()==1 && outputs[0].text=="A[Missing segment 2][Missing segment 3]");
    receive(7,2,"B"); receive(7,1,"A"); receive(7,3,"C");
    assert(outputs.size()==2 && outputs[1].text=="ABC" && outputs[1].supplement);
    receive(7,1,"A"); receive(7,2,"B"); receive(7,3,"C"); assert(outputs.size()==2);

    // 到期前有新 URC：不得跳過旧槽的交付邊界。
    reset(); receive(8,1,"A"); now_us=15LL*60*1000000+1; receive(9,1,"D");
    expire_concat_slots(); assert(outputs.size()==1 && outputs[0].text[0]=='A');

    // 背壓保留；解除後只交付一次，補齊仍能恢復。
    reset(); receive(7,1,"A"); blocked=true;
    now_us=15LL*60*1000000+1; expire_concat_slots(); assert(outputs.empty());
    blocked=false; now_us+=15LL*60*1000000+1; expire_concat_slots();
    receive(7,2,"B"); blocked=true; receive(7,3,"C"); assert(outputs.size()==1);
    blocked=false; receive(7,3,"C"); assert(outputs.size()==2 && outputs.back().text=="ABC");

    // 無新段不重發；窗口過後清理，五槽可再次接納。
    reset(); receive(7,1,"A"); now_us=15LL*60*1000000+1; expire_concat_slots();
    now_us+=15LL*60*1000000+1; expire_concat_slots(); expire_concat_slots();
    assert(outputs.size()==1);
    receive(7,1,"A"); assert(outputs.size()==1);
    for(int ref=20;ref<25;++ref) receive(ref,1,"D");
    assert(outputs.size()==1);

    // 競爭槽位與 ref 衝突：拒絕入隊時不可清掉已收到的段。
    reset(); for(int ref=20;ref<25;++ref) receive(ref,1,"A");
    blocked=true; assert(receive(25,1,"D").admission_blocked);
    blocked=false; receive(20,2,"B"); receive(20,3,"C");
    assert(outputs.size()==1 && outputs[0].text=="ABC" && !outputs[0].supplement);
    reset(); receive(7,1,"A"); blocked=true;
    assert(receive(7,1,"D","new").admission_blocked);
    blocked=false; receive(7,2,"B"); receive(7,3,"C");
    assert(outputs.size()==1 && outputs[0].text=="ABC");

    // 窗口內慢慢到段不刷新期限；結束時只交付新增版本，不重發相同 partial。
    reset(); receive(7,1,"A"); now_us=15LL*60*1000000+1; expire_concat_slots();
    now_us+=14LL*60*1000000; receive(7,2,"B"); expire_concat_slots();
    assert(outputs.size()==1);
    now_us+=60LL*1000000+1; blocked=true; expire_concat_slots(); assert(outputs.size()==1);
    blocked=false; expire_concat_slots();
    assert(outputs.size()==2 && outputs.back().text=="AB[Missing segment 3]" && !outputs.back().supplement);
    receive(7,1,"A"); receive(7,2,"B"); expire_concat_slots(); assert(outputs.size()==2);
    // 相同 ref／文字但新時間是新訊息，不可被退休指紋誤吞。
    receive(7,1,"A","new"); receive(7,2,"B","new"); receive(7,3,"C","new");
    assert(outputs.size()==3 && outputs.back().text=="ABC" && !outputs.back().supplement);
    // 完成指紋仍遵守既有十分鐘期限，不永久封鎖 ref。
    now_us+=10LL*60*1000000+1;
    receive(7,1,"A","new"); receive(7,2,"B","new"); receive(7,3,"D","new");
    assert(outputs.size()==4 && outputs.back().text=="ABD");

    // RAM 背壓重試須保留補充 metadata，不變更原文。
    outputs.clear(); blocked=true;
    assert(enqueue_pending_forward("synthetic", "ABC", "t", 1, true));
    assert(!retry_pending_forward() && outputs.empty());
    blocked=false; assert(retry_pending_forward());
    assert(outputs.size()==1 && outputs[0].text=="ABC" && outputs[0].supplement);
    assert(!retry_pending_forward());
}
