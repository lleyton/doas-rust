// This is essentially an almost 1 to 1 Rust port of https://github.com/Duncaen/OpenDoas/blob/master/timestamp.c
// I don't trust myself to implment this well, as timestamp files are a massive footgun.
// If anyone knows how to do this better, preferably without timestamp files, that would be appriciated.

use std::{fs::{File, rename}, time::Duration, os::unix::prelude::{AsRawFd, OpenOptionsExt}, path::PathBuf, io::ErrorKind};
use lazy_static::lazy_static;
use anyhow::{Result, anyhow, bail};
use nix::{unistd::{getppid, getsid, getuid, getgid, mkdir, getpid, unlink}, time::{clock_gettime, ClockId}, sys::{time::TimeSpec, stat::{futimens, fstat, stat, Mode}}, libc::{S_IFREG, timespec, S_IFDIR, O_NOFOLLOW, O_RDONLY, O_CREAT, O_EXCL}, errno::Errno};

lazy_static! {
  static ref TIMESTAMP_DIR: PathBuf = PathBuf::from("/run/doas");
}

struct ProcessTTYInfo {
    tty: i32,
    start_time: u64,
}

fn get_process_tty_info(pid: i32) -> Result<ProcessTTYInfo> {
    let process = procfs::process::Process::new(pid)?;
    let stat = process.stat()?;

    Ok(ProcessTTYInfo {
        tty: stat.tty_nr,
        start_time: stat.starttime,
    })
}

fn get_timestamp_file_path() -> Result<PathBuf> {
  let parent = getppid();
  let session_id = getsid(None)?;
  let tty_info = get_process_tty_info(parent.as_raw())?;
  // TODO: Is UID the real uid?
  let uid = getuid();

  Ok(PathBuf::from(format!("{}-{}-{}-{}-{}", parent.as_raw(), session_id.as_raw(), tty_info.tty, tty_info.start_time, uid)))
}

pub fn set_timestamp_file(file: &File, timeout: Duration) -> Result<()> {
  let boot_time = clock_gettime(ClockId::CLOCK_BOOTTIME)?;
  let real_time = clock_gettime(ClockId::CLOCK_REALTIME)?;
  let timeout = TimeSpec::from_duration(timeout);

  let fd = file.as_raw_fd();

  futimens(fd, &(boot_time + timeout), &(real_time + timeout))?;

  Ok(())
}

fn check_timestamp_file(file: &File, timeout: Duration) -> Result<bool> {
  let fd = file.as_raw_fd();
  let stat = fstat(fd)?;

  // TODO: Check if GID is proper
  if stat.st_uid != 0 || stat.st_gid != getgid().as_raw() || stat.st_mode != (S_IFREG | 0000) {
    return Err(anyhow!("timestamp uid, gid or mode wrong"))
  }

  if !(stat.st_atime != 0 || stat.st_atime_nsec != 0) {
    return Ok(false);
  }

  let access_time = TimeSpec::from_timespec(timespec {
    tv_sec: stat.st_atime,
    tv_nsec: stat.st_atime_nsec,
  });

  if !(stat.st_mtime != 0 || stat.st_mtime_nsec != 0) {
    return Ok(false);
  }

  let modified_time = TimeSpec::from_timespec(timespec {
    tv_sec: stat.st_mtime,
    tv_nsec: stat.st_mtime_nsec,
  });

  let boot_time = clock_gettime(ClockId::CLOCK_BOOTTIME)?;
  let real_time = clock_gettime(ClockId::CLOCK_REALTIME)?;
  let timeout = TimeSpec::from_duration(timeout);

  if (access_time < boot_time) || (modified_time < real_time) {
    return Ok(false);
  }

  if (access_time > (boot_time + timeout)) || (modified_time > (real_time + timeout)) {
    return Ok(false);
  }

  Ok(true)
}

pub struct OpenTimestampInfo {
  pub valid: bool,
  pub file: File
}

// TODO: Figure out when to error or just return valid false
pub fn open_timestamp_file(timeout: Duration) -> Result<OpenTimestampInfo> {
  let timestamp_dir_stat = stat(TIMESTAMP_DIR.as_path());

  match timestamp_dir_stat {
    Ok(stat) => {
      if stat.st_uid != 0 || stat.st_mode != (S_IFDIR | 0700) {
        bail!("incorrect permissions for timestamp directory");
      }
    }
    Err(Errno::ENOENT) => mkdir(TIMESTAMP_DIR.as_path(), Mode::S_IRWXU)?,
    Err(e) => bail!(e)
  }
  
  let path = TIMESTAMP_DIR.join(get_timestamp_file_path()?);

  let file_result = File::options().custom_flags(O_RDONLY|O_NOFOLLOW).open(&path);

  match file_result {
    Ok(file) => {
      Ok(OpenTimestampInfo {
        valid: check_timestamp_file(&file, timeout)?,
        file,
      })
    },
    Err(e) if e.kind() == ErrorKind::NotFound => {
      let tmp = TIMESTAMP_DIR.join(format!("tmp-{}", getpid().as_raw()));
      let file = File::options().custom_flags(O_RDONLY|O_CREAT|O_EXCL|O_NOFOLLOW).mode(0o000).open(&tmp)?;

      let futimens_result = futimens(file.as_raw_fd(), &TimeSpec::from_timespec(timespec { tv_sec: 0, tv_nsec: 0 }), &TimeSpec::from_timespec(timespec { tv_sec: 0, tv_nsec: 0 }));
      let rename_result = rename(&tmp, &path);

      if futimens_result.is_err() || rename_result.is_err() {
        drop(file);
        let _ = unlink(&tmp);

        futimens_result?;
        rename_result?;

        unreachable!();
      }

      Ok(OpenTimestampInfo {
        file,
        valid: false
      })
    }
    Err(e) => bail!(e)
  }
}

pub fn clear_timestamp() -> Result<()> {
  let path = TIMESTAMP_DIR.join(get_timestamp_file_path()?);
  match unlink(&path) {
    Ok(_) | Err(Errno::ENONET) => Ok(()),
    Err(e) => bail!(e)
  }
}