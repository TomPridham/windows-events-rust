fn main() {
    windows::build!(
        Windows::Win32::System::EventLog::*,
        Windows::Win32::System::Diagnostics::Debug::GetLastError,
        Windows::Win32::UI::WindowsAndMessaging::MessageBoxA
    )
}
