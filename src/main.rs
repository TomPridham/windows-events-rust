use bindings::Windows::Win32::System::{Diagnostics::Debug, EventLog};
use core::ffi::c_void;
use tokio::sync::mpsc::{unbounded_channel, UnboundedSender};

fn parse_event(event_handler: isize) -> String {
    const BUFFER_SIZE: usize = 65_000;
    let context = 0;
    let mut property_count = 0;
    // windows uses UTF16 strings, which means that their characters are 16 bytes wide instead
    // of the normal 8 in utf8
    let mut buffer: [u16; BUFFER_SIZE] = [0; BUFFER_SIZE];
    let mut used_buffer = 0;
    unsafe {
        EventLog::EvtRender(
            context,
            event_handler,
            EventLog::EvtRenderEventXml.0 as u32,
            BUFFER_SIZE as u32,
            buffer.as_mut_ptr() as *mut c_void,
            &mut used_buffer,
            &mut property_count,
        );
    }

    String::from_utf16_lossy(&buffer)
}

#[no_mangle]
extern "system" fn event_callback(
    action: EventLog::EVT_SUBSCRIBE_NOTIFY_ACTION,
    p_context: *const c_void,
    h_event: isize,
) -> u32 {
    if action == EventLog::EvtSubscribeActionError {
        eprintln!("Error in the subscriber: {:?}", action);
        return 1;
    }

    let xml_str = parse_event(h_event);

    let sender = unsafe {
        (p_context as *mut UnboundedSender<String>)
            .as_ref()
            .unwrap()
    };
    if sender.send(xml_str).is_err() {
        return 1;
    };
    0
}

#[tokio::main]
async fn main() {
    let (sender, mut receiver) = unbounded_channel();

    tokio::spawn(async move {
        let sender = Box::new(sender);

        let s = Box::leak(sender.clone());

        let session = 0;
        let signal_event = None;
        let channel_path = "Security";
        let query = "Event/System[EventID=4624 or EventID=4634 or EventID=1102]";
        let bookmark = 0;
        let context = s as *mut UnboundedSender<String> as *const c_void;
        let flags = EventLog::EvtSubscribeToFutureEvents.0 as u32;

        unsafe {
            EventLog::EvtSubscribe(
                session,
                signal_event,
                channel_path,
                query,
                bookmark,
                context,
                Some(event_callback),
                flags,
            );

            let evt_err = Debug::GetLastError().0;
            if evt_err != 0 {
                println!("{}", evt_err);
            }
        }
    });
    loop {
        if let Some(s_event) = receiver.recv().await {
            println!("{}", s_event);
        }
    }
}
