use std::{
    fs::{remove_file, File},
    io::{Read, Write},
    path::{Path, PathBuf},
    str::FromStr,
};

use anyhow::Result;
use serde::{de::DeserializeOwned, Serialize};

pub trait Storage<T> {
    fn save(&self, item: &T) -> Result<()>;
    fn load(&self) -> Result<T>;
    fn rm(self) -> Result<T>;
}

#[derive(Debug, Serialize, PartialEq, Clone)]
pub struct JsonFile {
    full_path: PathBuf,
}

impl JsonFile {
    pub fn new<P: AsRef<Path>>(dir: P, filename: String) -> Result<Self> {
        let mut path = PathBuf::new();
        path.push(dir);
        path.push(filename);

        Ok(Self { full_path: path })
    }
}

impl<T: Serialize + DeserializeOwned> Storage<T> for JsonFile {
    fn save(&self, data: &T) -> Result<()> {
        let json = serde_json::to_string(data)?;
        let mut file = File::create(self.full_path.clone())?;
        file.write_all(json.as_bytes())?;

        Ok(())
    }

    fn load(&self) -> Result<T> {
        let mut file = File::open(self.full_path.clone())?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;
        let data: T = serde_json::from_str(&contents)?;

        Ok(data)
    }

    fn rm(self) -> Result<T> {
        let item = self.load()?;
        remove_file(self.full_path)?;

        Ok(item)
    }
}
