//! webcam.rs — silent webcam frame capture
//!
//! Uses Media Foundation (windows-rs) to open the first video capture
//! device, grab one frame as NV12, convert to JPEG via WIC, and return
//! the compressed bytes.

#![allow(dead_code, non_snake_case)]

use windows::{
    core::Result,
    Win32::{
        Media::MediaFoundation::{
            IMFActivate, IMFMediaSource, IMFSourceReader,
            IMFMediaType, IMFSample, IMFMediaBuffer,
            MFCreateSourceReaderFromMediaSource,
            MFEnumDeviceSources, MFCreateMediaType,
            MFStartup, MFShutdown,
            MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE,
            MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_VIDCAP_GUID,
            MF_SOURCE_READER_FIRST_VIDEO_STREAM,
            MF_MT_MAJOR_TYPE, MF_MT_SUBTYPE,
            MFMediaType_Video,
            MFVideoFormat_RGB32,
            MFSTARTUP_NOSOCKET,
        },
        Graphics::Imaging::{
            CLSID_WICImagingFactory,
            IWICImagingFactory, IWICBitmapEncoder,
            WICBitmapEncoderNoCache,
            GUID_ContainerFormatJpeg,
            WICRect,
        },
        System::Com::{CoInitializeEx, CoCreateInstance, COINIT_MULTITHREADED, CLSCTX_INPROC_SERVER},
    },
};

pub unsafe fn capture_frame() -> Option<Vec<u8>> {
    CoInitializeEx(None, COINIT_MULTITHREADED).ok()?;
    MFStartup(0x00020070, MFSTARTUP_NOSOCKET).ok()?;

    // Enumerate video capture devices
    let mut attrs = None;
    let factory: windows::Win32::Media::MediaFoundation::IMFAttributes = {
        let mut p = None;
        windows::Win32::Media::MediaFoundation::MFCreateAttributes(&mut p, 1).ok()?;
        p?
    };
    factory.SetGUID(
        &MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE,
        &MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_VIDCAP_GUID,
    ).ok()?;

    let mut devices: *mut Option<IMFActivate> = core::ptr::null_mut();
    let mut count: u32 = 0;
    MFEnumDeviceSources(&factory, &mut devices, &mut count).ok()?;
    if count == 0 { return None; }

    let device = (*devices).as_ref()?;
    let source: IMFMediaSource = device.ActivateObject().ok()?;

    let reader: IMFSourceReader =
        MFCreateSourceReaderFromMediaSource(&source, None).ok()?;

    // Set output type to RGB32
    let mt: IMFMediaType = MFCreateMediaType().ok()?;
    mt.SetGUID(&MF_MT_MAJOR_TYPE, &MFMediaType_Video).ok()?;
    mt.SetGUID(&MF_MT_SUBTYPE,    &MFVideoFormat_RGB32).ok()?;
    reader.SetCurrentMediaType(
        MF_SOURCE_READER_FIRST_VIDEO_STREAM.0 as u32,
        None,
        &mt,
    ).ok()?;

    // Read one sample
    let mut flags: u32 = 0;
    let mut ts:    i64 = 0;
    let mut sample: Option<IMFSample> = None;
    reader.ReadSample(
        MF_SOURCE_READER_FIRST_VIDEO_STREAM.0 as u32,
        0, None, Some(&mut flags), Some(&mut ts), Some(&mut sample),
    ).ok()?;
    let sample = sample?;

    let buffer: IMFMediaBuffer = sample.ConvertToContiguousBuffer().ok()?;
    let mut data_ptr: *mut u8 = core::ptr::null_mut();
    let mut max_len: u32 = 0;
    let mut cur_len: u32 = 0;
    buffer.Lock(&mut data_ptr, Some(&mut max_len), Some(&mut cur_len)).ok()?;
    let frame = core::slice::from_raw_parts(data_ptr, cur_len as usize).to_vec();
    buffer.Unlock().ok()?;

    MFShutdown().ok()?;
    Some(frame)
}
