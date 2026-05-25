//! webcam.rs — Capture a single JPEG frame from the default webcam
//!
//! Uses Media Foundation (windows-rs 0.58) to open the first video
//! capture device, pull one sample, and return the raw bytes.

#![allow(dead_code, non_snake_case)]

use windows::{
    core::Result,
    Win32::Media::MediaFoundation::{
        MFCreateMediaType, MFCreateSourceReaderFromURL,
        MFStartup, MFShutdown, MFEnumDeviceSources,
        IMFMediaType, IMFSourceReader,
        MF_VERSION, MFSTARTUP_NOSOCKET,
        MF_SOURCE_READER_FIRST_VIDEO_STREAM,
        MFMediaType_Video,
        MFVideoFormat_MJPG,
        MF_MT_MAJOR_TYPE, MF_MT_SUBTYPE,
        MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE,
        MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_VIDCAP_GUID,
    },
    Win32::System::Com::{CoInitializeEx, CoUninitialize, COINIT_MULTITHREADED},
};

/// Capture one JPEG frame. Returns raw MJPEG bytes on success.
pub fn capture_frame() -> Result<Vec<u8>> {
    unsafe {
        CoInitializeEx(None, COINIT_MULTITHREADED)?;
        MFStartup(MF_VERSION, MFSTARTUP_NOSOCKET)?;

        let frame = capture_inner();

        MFShutdown()?;
        CoUninitialize();
        frame
    }
}

unsafe fn capture_inner() -> Result<Vec<u8>> {
    // ------------------------------------------------------------------
    // 1. Enumerate video capture devices.
    // ------------------------------------------------------------------
    use windows::Win32::Media::MediaFoundation::{
        MFCreateAttributes, IMFActivate,
    };

    let mut attrs = MFCreateAttributes(1)?;
    attrs.SetGUID(
        &MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE,
        &MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_VIDCAP_GUID,
    )?;

    let mut devices: *mut Option<IMFActivate> = core::ptr::null_mut();
    let mut count: u32 = 0;
    MFEnumDeviceSources(&attrs, &mut devices, &mut count)?;
    if count == 0 {
        return Err(windows::core::Error::from_win32());
    }

    // Take the first device.
    let device = (*devices).as_ref().unwrap().clone();

    // ------------------------------------------------------------------
    // 2. Create source reader.
    // ------------------------------------------------------------------
    let source = device.ActivateObject::<windows::Win32::Media::MediaFoundation::IMFMediaSource>()?;
    let reader = windows::Win32::Media::MediaFoundation::MFCreateSourceReaderFromMediaSource(
        &source, None,
    )?;

    // ------------------------------------------------------------------
    // 3. Set MJPEG output type — windows-rs 0.58: MFCreateMediaType() returns a value.
    // ------------------------------------------------------------------
    let mt: IMFMediaType = MFCreateMediaType()?;
    mt.SetGUID(&MF_MT_MAJOR_TYPE, &MFMediaType_Video)?;
    mt.SetGUID(&MF_MT_SUBTYPE,    &MFVideoFormat_MJPG)?;
    reader.SetCurrentMediaType(
        MF_SOURCE_READER_FIRST_VIDEO_STREAM.0 as u32,
        None,
        &mt,
    )?;

    // ------------------------------------------------------------------
    // 4. Read one sample.
    // ------------------------------------------------------------------
    let mut flags: u32 = 0;
    let mut timestamp: i64 = 0;
    let mut stream_index: u32 = 0;
    let sample = reader.ReadSample(
        MF_SOURCE_READER_FIRST_VIDEO_STREAM.0 as u32,
        0,
        Some(&mut stream_index),
        Some(&mut flags),
        Some(&mut timestamp),
    )?;

    let sample = match sample {
        Some(s) => s,
        None    => return Err(windows::core::Error::from_win32()),
    };

    // ------------------------------------------------------------------
    // 5. Copy buffer bytes.
    // ------------------------------------------------------------------
    let buf = sample.ConvertToContiguousBuffer()?;
    let mut ptr: *mut u8 = core::ptr::null_mut();
    let mut max_len: u32 = 0;
    let mut cur_len: u32 = 0;
    buf.Lock(&mut ptr, Some(&mut max_len), Some(&mut cur_len))?;
    let data = core::slice::from_raw_parts(ptr, cur_len as usize).to_vec();
    buf.Unlock()?;

    Ok(data)
}
