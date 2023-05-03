use std::fmt::Debug;
use std::marker::PhantomData;
use cyfs_base::*;
use serde::{Serialize, Deserialize};
use std::ops::{Deref, DerefMut};
use crate::*;
use crate::error_code::*;

pub trait JSONObjType: 'static + RawEncode + Clone + Debug + Send + Sync {
    fn obj_type() -> u16;
}

#[derive(Clone, Debug, RawEncode, RawDecode)]
pub struct JSONDescContent<T: JSONObjType> {
    obj_type: u16,
    content_hash: HashValue,
    #[cyfs(skip)]
    _p: PhantomData<T>,
}

impl<T: JSONObjType> DescContent for JSONDescContent<T> {
    fn obj_type() -> u16 {
        T::obj_type()
    }

    type OwnerType = Option<ObjectId>;
    type AreaType = SubDescNone;
    type AuthorType = SubDescNone;
    type PublicKeyType = SubDescNone;
}

#[derive(Clone, Debug, RawEncode, RawDecode)]
pub struct JSONBodyContent(pub Vec<u8>);

impl Deref for JSONBodyContent {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for JSONBodyContent {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl BodyContent for JSONBodyContent {

    fn version(&self) -> u8 {
        0
    }

    fn format(&self) -> u8 {
        OBJECT_CONTENT_CODEC_FORMAT_RAW
    }
}

pub type JSONObjectType<T> = NamedObjType<JSONDescContent<T>, JSONBodyContent>;
pub type JSONObjectBuilder<T> = NamedObjectBuilder<JSONDescContent<T>, JSONBodyContent>;
pub type JSONObject<T> = NamedObjectBase<JSONObjectType<T>>;

pub trait DSGJSON<T: Serialize + for<'a> Deserialize<'a>, A: JSONObjType> {
    fn new(dec_id: ObjectId, owner_id: ObjectId, obj_type: u16, obj: &T) -> BuckyResult<JSONObject<A>>;
    fn get(&self) -> BuckyResult<T>;
}

pub trait DSGJSONType {
    fn get_json_obj_type(&self) -> u16;
}

impl<T: JSONObjType> DSGJSONType for NamedObjectBase<JSONObjectType<T>> {
    fn get_json_obj_type(&self) -> u16 {
        self.desc().content().obj_type
    }
}

pub trait Verifier {
    fn verify_body(&self) -> bool;
}

impl <T: Serialize + for<'a> Deserialize<'a>, A: JSONObjType> DSGJSON<T, A> for NamedObjectBase<JSONObjectType<A>> {
    fn new(dec_id: ObjectId, owner_id: ObjectId, obj_type: u16, obj: &T) -> BuckyResult<JSONObject<A>> {
        let body = JSONBodyContent(serde_json::to_vec(obj).map_err(|e| {
            app_err!(ERROR_FAILED, "serde json err:{}", e)
        })?);

        let desc = JSONDescContent { obj_type, content_hash: hash_data(body.as_slice()), _p: Default::default() };

        Ok(JSONObjectBuilder::new(desc, body).owner(owner_id).dec_id(dec_id).build())
    }

    fn get(&self) -> BuckyResult<T> {
        let body = self.body().as_ref().unwrap().content();
        serde_json::from_slice(body.as_ref()).map_err(|e| {
            let str = String::from_utf8_lossy(body.as_slice()).to_string();
            app_err!(ERROR_FAILED, "parse {} body err:{}", str, e)
        })
    }

}

impl<A: JSONObjType> Verifier for NamedObjectBase<JSONObjectType<A>> {
    fn verify_body(&self) -> bool {
        if self.body().is_none() {
            return false;
        }

        let body = self.body().as_ref().unwrap().content();
        if hash_data(body.as_slice()) == self.desc().content().content_hash {
            true
        } else {
            false
        }
    }
}
