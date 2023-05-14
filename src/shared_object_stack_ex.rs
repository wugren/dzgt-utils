use std::marker::PhantomData;
use cyfs_lib::*;
use std::ops::{Deref};
use std::path::PathBuf;
use cyfs_base::*;
use async_trait::async_trait;
use std::sync::{Arc, Weak};
use std::time::Duration;
use crate::*;
use async_std::future::Future;
use cyfs_util::{EventListenerAsyncRoutine};

#[async_trait]
pub trait SharedCyfsStackExEndpoint<P, R>: Send + Sync + 'static
    where P: 'static + ObjectType + Send + Sync,
          <P as ObjectType>::ContentType: BodyContent + for<'a> RawDecode<'a>,
          <P as ObjectType>::DescType: for<'a> RawDecodeWithContext<'a, NamedObjectContext>,
          R: 'static + ObjectType + Send + Sync,
          <R as ObjectType>::ContentType: BodyContent + cyfs_base::RawEncode,
          <R as ObjectType>::DescType: RawEncodeWithContext<NamedObjectContext>, {
    async fn call(&self, req_info: &NONInputRequestCommon, param: NamedObjectBase<P>) -> BuckyResult<NamedObjectBase<R>>;
}

#[async_trait]
impl<P, R, F, Fut> SharedCyfsStackExEndpoint<P, R> for F
    where P: 'static + ObjectType + Send + Sync,
          <P as ObjectType>::ContentType: BodyContent + for<'a> RawDecode<'a>,
          <P as ObjectType>::DescType: for<'a> RawDecodeWithContext<'a, NamedObjectContext>,
          R: 'static + ObjectType + Send + Sync,
          <R as ObjectType>::ContentType: BodyContent + cyfs_base::RawEncode,
          <R as ObjectType>::DescType: RawEncodeWithContext<NamedObjectContext>,
          F: Send + Sync + 'static + Fn(&'static NONInputRequestCommon, NamedObjectBase<P>) -> Fut,
          Fut: Send + 'static + Future<Output=BuckyResult<NamedObjectBase<R>>>,
{
    async fn call(&self, req_info: &NONInputRequestCommon, param: NamedObjectBase<P>) -> BuckyResult<NamedObjectBase<R>> {
        let static_req_info: &'static NONInputRequestCommon = unsafe {std::mem::transmute(req_info)};
        let fut = (self)(static_req_info, param);
        fut.await
    }
}

pub struct SharedCyfsStackServer {
    stack: Arc<SharedCyfsStack>,
    name: String,
}
pub type SharedCyfsStackServerRef = Arc<SharedCyfsStackServer>;
pub type SharedCyfsStackServerWeakRef = Weak<SharedCyfsStackServer>;

impl Deref for SharedCyfsStackServer {
    type Target = Arc<SharedCyfsStack>;

    fn deref(&self) -> &Self::Target {
        &self.stack
    }
}

struct OnHandler<P, R>
    where P: 'static + ObjectType + Send + Sync,
          <P as ObjectType>::ContentType: BodyContent + for<'a> RawDecode<'a>,
          <P as ObjectType>::DescType: for<'a> RawDecodeWithContext<'a, NamedObjectContext>,
          R: 'static + ObjectType + Send + Sync,
          <R as ObjectType>::ContentType: BodyContent + cyfs_base::RawEncode,
          <R as ObjectType>::DescType: RawEncodeWithContext<NamedObjectContext> {
    ep: Box<dyn SharedCyfsStackExEndpoint<P, R>>,
    _p: PhantomData<P>,
    _r: PhantomData<R>,
}

#[async_trait]
impl<P, R> EventListenerAsyncRoutine<RouterHandlerPostObjectRequest, RouterHandlerPostObjectResult> for OnHandler<P, R>
    where P: 'static + ObjectType + Send + Sync,
          <P as ObjectType>::ContentType: BodyContent + for<'a> RawDecode<'a>,
          <P as ObjectType>::DescType: for<'a> RawDecodeWithContext<'a, NamedObjectContext>,
          R: 'static + ObjectType + Send + Sync,
          <R as ObjectType>::ContentType: BodyContent + cyfs_base::RawEncode,
          <R as ObjectType>::DescType: RawEncodeWithContext<NamedObjectContext> {
    async fn call(&self, param: &RouterHandlerPostObjectRequest) -> BuckyResult<RouterHandlerPostObjectResult> {
        let obj_type = if param.request.object.object.is_some() {
            param.request.object.object.as_ref().unwrap().obj_type()
        } else {
            let any_obj = AnyNamedObject::clone_from_slice(param.request.object.object_raw.as_slice())?;
            any_obj.obj_type()
        };
        log::debug!("------># recv obj type : {} source:{}", obj_type, param.request.common.source.to_string());
        if obj_type != P::obj_type() {
            log::error!("recv unexpect obj type:{} id:{} source:{}", obj_type, param.request.object.object_id.to_string(), param.request.common.source.to_string());
            return Ok(
                RouterHandlerPostObjectResult {
                    action: RouterHandlerAction::Pass,
                    request: None,
                    response: None,
                });
        }
        let req = NamedObjectBase::<P>::clone_from_slice(param.request.object.object_raw.as_slice())?;
        match self.ep.call(&param.request.common, req).await {
            Ok(ret) => {
                let object_id = ret.desc().object_id();
                let object_raw = ret.to_vec()?;
                Ok(RouterHandlerPostObjectResult {
                    action: RouterHandlerAction::Response,
                    request: None,
                    response: Some(Ok(NONPostObjectInputResponse {
                        object: Some(NONObjectInfo {
                            object_id,
                            object_raw,
                            object: None,
                        })
                    })),
                })
            },
            Err(e) => {
                log::error!("handle obj {} err {}", param.request.object.object_id.to_string(), &e);
                Ok(RouterHandlerPostObjectResult {
                    action: RouterHandlerAction::Response,
                    request: None,
                    response: Some(Err(e))
                })
            }
        }
    }
}

impl SharedCyfsStackServer {
    pub fn new(name: String, stack: Arc<SharedCyfsStack>) -> SharedCyfsStackServerRef {
        SharedCyfsStackServerRef::new(Self {
            stack,
            name,
        })
    }

    pub fn get_stack(&self) -> &Arc<SharedCyfsStack> {
        &self.stack
    }

    pub async fn attach_handler<P, R>(self: &SharedCyfsStackServerRef, path: &str, access: Option<AccessString>, ep: impl SharedCyfsStackExEndpoint<P, R>) -> BuckyResult<()>
        where P: 'static + ObjectType + Send + Sync,
              <P as ObjectType>::ContentType: BodyContent + for<'a> RawDecode<'a>,
              <P as ObjectType>::DescType: for<'a> RawDecodeWithContext<'a, NamedObjectContext>,
              R: 'static + ObjectType + Send + Sync,
              <R as ObjectType>::ContentType: BodyContent + cyfs_base::RawEncode,
              <R as ObjectType>::DescType: RawEncodeWithContext<NamedObjectContext>  {
        let listener = OnHandler {
            ep: Box::new(ep),
            _p: Default::default(),
            _r: Default::default(),
        };

        if access.is_some() {
            self.stack.root_state_meta_stub(None, None).add_access(GlobalStatePathAccessItem {
                path: path.to_string(),
                access: GlobalStatePathGroupAccess::Default(access.as_ref().unwrap().value())
            }).await?;
        } else {
            let mut access = AccessString::new(0);
            access.set_group_permissions(AccessGroup::CurrentDevice, AccessPermissions::Full);
            access.set_group_permissions(AccessGroup::OthersDec, AccessPermissions::Full);
            access.set_group_permissions(AccessGroup::CurrentZone, AccessPermissions::Full);
            self.stack.root_state_meta_stub(None, None).add_access(GlobalStatePathAccessItem {
                path: path.to_string(),
                access: GlobalStatePathGroupAccess::Default(access.value())
            }).await?;
        }

        self.stack.router_handlers().add_handler(RouterHandlerChain::Handler,
                                                 format!("{}_{}", self.name.as_str(), path.replace("/", "_")).as_str(),
                                                 0,
                                                 None,
                                                 Some(path.to_string()),
                                                 RouterHandlerAction::Default,
                                                 Some(Box::new(listener)))?;
        Ok(())
    }
}

pub struct CyfsPath {
    pub target: ObjectId,
    pub target_dec_id: ObjectId,
    pub req_path: String,
}

impl CyfsPath {
    pub fn new(target: ObjectId, target_dec_id: ObjectId, req_path: &str) -> Self {
        Self {
            target,
            target_dec_id,
            req_path: req_path.to_string()
        }
    }

    pub fn to_path(&self) -> String {
        format!("/{}/{}/{}", self.target.to_string(), self.target_dec_id.to_string(), self.req_path)
    }

    pub fn parse(path: &str) -> BuckyResult<Self> {
        if !path.starts_with("/") {
            return Err(cyfs_err!(BuckyErrorCode::InvalidFormat, "parse {} err", path));
        }
        let path_ref = &path[1..];
        let pos = path_ref.find("/");
        if pos.is_none() {
            return Err(cyfs_err!(BuckyErrorCode::InvalidFormat, "parse {} err", path));
        }
        let target = &path_ref[..pos.unwrap()];

        let path_ref = &path_ref[pos.unwrap() + 1..];
        let pos = path_ref.find("/");
        if pos.is_none() {
            return Err(cyfs_err!(BuckyErrorCode::InvalidFormat, "parse {} err", path));
        }
        let target_dec_id = &path_ref[..pos.unwrap()];

        let req_path = path_ref[pos.unwrap() + 1..].to_string();
        Ok(Self {
            target: ObjectId::from_base58(target)?,
            target_dec_id: ObjectId::from_base58(target_dec_id)?,
            req_path
        })
    }
}

#[cfg(feature = "stack_cache")]
lazy_static::lazy_static! {
    static ref OBJ_CACHE: mini_moka::sync::Cache<ObjectId, Arc<Vec<u8>>> = mini_moka::sync::CacheBuilder::new(10000).time_to_live(Duration::from_secs(600)).build();
}

#[async_trait::async_trait]
pub trait DownloadProgressEvent: 'static + Send + Sync {
    async fn call(&self, state: TransTaskOnAirState);
}

#[async_trait]
impl<F, Fut> DownloadProgressEvent for F
    where F: Send + Sync + 'static + Fn(TransTaskOnAirState) -> Fut,
          Fut: Send + 'static + Future<Output=()>,
{
    async fn call(&self, state: TransTaskOnAirState) {
        let fut = (self)(state);
        fut.await
    }
}

#[async_trait::async_trait]
pub trait CyfsClient: Send + Sync + 'static {
    fn local_device(&self) -> Device;
    async fn resolve_ood(&self, object_id: ObjectId) -> BuckyResult<ObjectId>;
    async fn sign_object(&self, object_id: ObjectId, object_raw: Vec<u8>) -> BuckyResult<Vec<u8>>;
    async fn sign_object2<T: ObjectType + Sync + Send, O: for <'a> RawDecode<'a>>(&self, obj: &NamedObjectBase<T>) -> BuckyResult<O>
        where <T as cyfs_base::ObjectType>::ContentType: cyfs_base::BodyContent + cyfs_base::RawEncode,
              <T as cyfs_base::ObjectType>::DescType: RawEncodeWithContext<cyfs_base::NamedObjectContext>;
    async fn get_object<T: for <'a> RawDecode<'a>>(
        &self,
        target: Option<ObjectId>,
        object_id: ObjectId
    ) -> BuckyResult<T>;
    async fn get_object_by_path<T: for<'a> RawDecode<'a>> (
        &self,
        target: Option<ObjectId>,
        dec_id: ObjectId,
        path: &str
    ) -> BuckyResult<T>;
    async fn put_object_with_resp(
        &self,
        req_path: &str,
        object_id: ObjectId,
        object_raw: Vec<u8>
    ) -> BuckyResult<Vec<u8>>;
    async fn put_object_with_resp2<T: RawEncode + for <'a> RawDecode<'a>>(
        &self,
        req_path: &str,
        object_id: ObjectId,
        object_raw: Vec<u8>
    ) -> BuckyResult<T>;
    async fn download(
        &self,
        file_id: ObjectId,
        save_path: Option<PathBuf>,
        source_list: Vec<DeviceId>,
        req_path: Option<String>,
        progress_event: Option<impl DownloadProgressEvent>) -> BuckyResult<()>;
    #[cfg(feature = "stack_cache")]
    fn get_from_cache<T: for <'a> RawDecode<'a>>(&self, object_id: &ObjectId) -> BuckyResult<Option<T>>;
    #[cfg(feature = "stack_cache")]
    fn insert_to_cache(&self, object_id: ObjectId, object_raw: Arc<Vec<u8>>);
}

#[async_trait::async_trait]
impl CyfsClient for SharedCyfsStack {
    fn local_device(&self) -> Device {
        self.local_device()
    }

    async fn resolve_ood(&self, object_id: ObjectId) -> BuckyResult<ObjectId> {
        let resp = self.util().resolve_ood(UtilResolveOODRequest {
            common: UtilOutputRequestCommon {
                req_path: None,
                dec_id: None,
                target: None,
                flags: 0
            },
            object_id,
            owner_id: None
        }).await?;

        let ood_id = resp.device_list[0].object_id().clone();
        Ok(ood_id)
    }

    async fn sign_object(&self, object_id: ObjectId, object_raw: Vec<u8>) -> BuckyResult<Vec<u8>> {
        let flags = CRYPTO_REQUEST_FLAG_SIGN_BY_DEVICE | CRYPTO_REQUEST_FLAG_SIGN_PUSH_DESC;
        let resp = self.crypto().sign_object(CryptoSignObjectRequest {
            common: CryptoOutputRequestCommon {
                req_path: None,
                dec_id: None,
                target: None,
                flags
            },
            flags,
            object: NONObjectInfo {
                object_id,
                object_raw,
                object: None
            }
        }).await?;

        Ok(resp.object.unwrap().object_raw)
    }

    async fn sign_object2<T: ObjectType + Sync + Send, O: for<'a> RawDecode<'a>>(&self, obj: &NamedObjectBase<T>) -> BuckyResult<O>
        where <T as ObjectType>::ContentType: BodyContent + RawEncode, <T as ObjectType>::DescType: RawEncodeWithContext<NamedObjectContext> {
        let object_id = obj.desc().calculate_id();
        let signed = self.sign_object(object_id, obj.to_vec()?).await?;
        O::clone_from_slice(signed.as_slice())
    }

    async fn get_object<T: for <'a> RawDecode<'a>>(&self, target: Option<ObjectId>, object_id: ObjectId) -> BuckyResult<T> {
        #[cfg(feature = "stack_cache")]
        {
            if let Some(object_raw) = OBJ_CACHE.get(&object_id) {
                return T::clone_from_slice(object_raw.as_slice());
            }
        }

        let resp = self.non_service().get_object(NONGetObjectOutputRequest {
            common: NONOutputRequestCommon {
                req_path: None,
                source: None,
                dec_id: None,
                level: if target.is_none() {NONAPILevel::NOC} else {NONAPILevel::Router},
                target,
                flags: 0
            },
            object_id: object_id.clone(),
            inner_path: None
        }).await?;

        #[cfg(feature = "stack_cache")]
        {
            OBJ_CACHE.insert(object_id, Arc::new(resp.object.object_raw.clone()));
        }
        T::clone_from_slice(resp.object.object_raw.as_slice())
    }

    async fn get_object_by_path<T: for<'a> RawDecode<'a>>(&self, target: Option<ObjectId>, dec_id: ObjectId, path: &str) -> BuckyResult<T> {
        let resp = self.root_state_accessor_stub(target, Some(dec_id)).get_object_by_path(path).await?;

        #[cfg(feature = "stack_cache")]
        {
            OBJ_CACHE.insert(resp.object.object_id, Arc::new(resp.object.object_raw.clone()));
        }

        T::clone_from_slice(resp.object.object_raw.as_slice())
    }

    async fn put_object_with_resp(&self, req_path: &str, object_id: ObjectId, object_raw: Vec<u8>) -> BuckyResult<Vec<u8>> {
        let cyfs_path = CyfsPath::parse(req_path)?;
        let path = RequestGlobalStatePath {
            global_state_category: None,
            global_state_root: None,
            dec_id: Some(cyfs_path.target_dec_id),
            req_path: Some(cyfs_path.req_path)
        };
        // let object_raw = self.sign_object(object_id.clone(), object_raw).await?;
        let resp = self.non_service().post_object(NONPostObjectOutputRequest {
            common: NONOutputRequestCommon {
                req_path: Some(path.to_string()),
                source: None,
                dec_id: None,
                level: NONAPILevel::Router,
                target: Some(cyfs_path.target),
                flags: 0
            },
            object: NONObjectInfo {
                object_id,
                object_raw,
                object: None
            }
        }).await?;

        if resp.object.is_none() {
            Err(cyfs_err!(BuckyErrorCode::InvalidData, "resp data is none"))
        } else {
            let object_raw = resp.object.unwrap().object_raw;
            Ok(object_raw)
        }
    }

    async fn put_object_with_resp2<T: RawEncode + for <'a> RawDecode<'a>>(&self, req_path: &str, object_id: ObjectId, object_raw: Vec<u8>) -> BuckyResult<T> {
        let cyfs_path = CyfsPath::parse(req_path)?;
        let path = RequestGlobalStatePath {
            global_state_category: None,
            global_state_root: None,
            dec_id: Some(cyfs_path.target_dec_id),
            req_path: Some(cyfs_path.req_path)
        };

        let resp = self.non_service().post_object(NONPostObjectOutputRequest {
            common: NONOutputRequestCommon {
                req_path: Some(path.to_string()),
                source: None,
                dec_id: None,
                level: NONAPILevel::Router,
                target: Some(cyfs_path.target),
                flags: 0
            },
            object: NONObjectInfo {
                object_id,
                object_raw,
                object: None
            }
        }).await?;

        if resp.object.is_none() {
            Err(cyfs_err!(BuckyErrorCode::InvalidData, "resp data is none"))
        } else {
            let object_raw = resp.object.unwrap().object_raw;
            Ok(T::clone_from_slice(object_raw.as_slice())?)
        }
    }

    async fn download(&self, file_id: ObjectId, save_path: Option<PathBuf>, source_list: Vec<DeviceId>, req_path: Option<String>, progress_event: Option<impl DownloadProgressEvent>) -> BuckyResult<()> {
        let task_id = self.trans().create_task(TransCreateTaskOutputRequest {
            common: NDNOutputRequestCommon {
                req_path,
                dec_id: None,
                level: NDNAPILevel::NDC,
                target: None,
                referer_object: vec![],
                flags: 0
            },
            object_id: file_id,
            local_path: if save_path.is_none() {PathBuf::new()} else {save_path.unwrap()},
            device_list: source_list,
            group: None,
            context: None,
            auto_start: true
        }).await?.task_id;

        loop {
            let state = self.trans().get_task_state(TransGetTaskStateOutputRequest {
                common: NDNOutputRequestCommon {
                    req_path: None,
                    dec_id: None,
                    level: NDNAPILevel::NDC,
                    target: None,
                    referer_object: vec![],
                    flags: 0
                },
                task_id: task_id.clone()
            }).await?;

            match state.state {
                TransTaskState::Pending => {

                }
                TransTaskState::Downloading(state) => {
                    if progress_event.is_some() {
                        progress_event.as_ref().unwrap().call(state).await;
                    }
                }
                TransTaskState::Paused | TransTaskState::Canceled => {
                    let msg = format!("download {} task abnormal exit.", file_id.to_string());
                    log::error!("{}", msg.as_str());
                    return Err(BuckyError::new(BuckyErrorCode::Failed, msg))
                }
                TransTaskState::Finished(_) => {
                    break;
                }
                TransTaskState::Err(err) => {
                    let msg = format!("download {} failed.{}", file_id.to_string(), err);
                    log::error!("{}", msg.as_str());
                    return Err(BuckyError::new(err, msg))
                }
            }
            async_std::task::sleep(Duration::from_secs(1)).await;
        }
        self.trans().delete_task(TransTaskOutputRequest {
            common: NDNOutputRequestCommon {
                req_path: None,
                dec_id: None,
                level: NDNAPILevel::NDC,
                target: None,
                referer_object: vec![],
                flags: 0
            },
            task_id
        }).await?;
        Ok(())
    }

    #[cfg(feature = "stack_cache")]
    fn get_from_cache<T: for<'a> RawDecode<'a>>(&self, object_id: &ObjectId) -> BuckyResult<Option<T>> {
        if let Some(object_raw) = OBJ_CACHE.get(object_id) {
            Ok(Some(T::clone_from_slice(object_raw.as_slice())?))
        } else {
            Ok(None)
        }
    }

    #[cfg(feature = "stack_cache")]
    fn insert_to_cache(&self, object_id: ObjectId, object_raw: Arc<Vec<u8>>) {
        OBJ_CACHE.insert(object_id, object_raw);
    }
}

pub type SharedCyfsStackRef = Arc<SharedCyfsStack>;

#[async_trait::async_trait]
pub trait CyfsNOC {
    async fn get_object_from_noc<T: for <'a> RawDecode<'a>>(&self, object_id: ObjectId) -> BuckyResult<T>;
    async fn put_object_to_noc<T: ObjectType + Sync + Send>(&self, obj: &NamedObjectBase<T>, access: Option<AccessString>) -> BuckyResult<ObjectId>
        where <T as cyfs_base::ObjectType>::ContentType: cyfs_base::BodyContent + cyfs_base::RawEncode,
              <T as cyfs_base::ObjectType>::DescType: RawEncodeWithContext<cyfs_base::NamedObjectContext>;
    async fn update_object_meta_of_noc(&self, object_id: ObjectId, access: AccessString) -> BuckyResult<()>;
    async fn gen_aes_key_and_encrypt(&self) -> BuckyResult<(AesKey, Vec<u8>)>;
    async fn decrypt_aes_key(&self, encrypt_aes_key: Vec<u8>) -> BuckyResult<AesKey>;
}

#[async_trait::async_trait]
impl CyfsNOC for SharedCyfsStack {
    async fn get_object_from_noc<T: for<'a> RawDecode<'a>>(&self, object_id: ObjectId) -> BuckyResult<T> {
        self.get_object(None, object_id).await
    }

    async fn put_object_to_noc<T: ObjectType + Sync + Send>(&self, obj: &NamedObjectBase<T>, access: Option<AccessString>) -> BuckyResult<ObjectId>
        where <T as cyfs_base::ObjectType>::ContentType: cyfs_base::BodyContent + cyfs_base::RawEncode,
              <T as cyfs_base::ObjectType>::DescType: RawEncodeWithContext<cyfs_base::NamedObjectContext> {
        let object_id = obj.desc().calculate_id();
        let object_raw = obj.to_vec()?;
        #[cfg(not(feature = "stack_cache"))]
        {
            self.non_service().put_object(NONPutObjectOutputRequest { common: NONOutputRequestCommon {
                req_path: None,
                source: None,
                dec_id: None,
                level: NONAPILevel::NOC,
                target: None,
                flags: 0
            }, object: NONObjectInfo {
                object_id,
                object_raw,
                object: None
            },
                access
            }).await?;
        }
        #[cfg(feature = "stack_cache")]
        {
            self.non_service().put_object(NONPutObjectOutputRequest { common: NONOutputRequestCommon {
                req_path: None,
                source: None,
                dec_id: None,
                level: NONAPILevel::NOC,
                target: None,
                flags: 0
            }, object: NONObjectInfo {
                object_id: object_id.clone(),
                object_raw: object_raw.clone(),
                object: None
            },
                access
            }).await?;
            OBJ_CACHE.insert(object_id, Arc::new(object_raw));
        }

        Ok(object_id)
    }

    async fn update_object_meta_of_noc(&self, object_id: ObjectId, access: AccessString) -> BuckyResult<()> {
        let _resp = self.non_service().update_object_meta(NONUpdateObjectMetaOutputRequest {
            common: NONOutputRequestCommon {
                req_path: None,
                source: None,
                dec_id: None,
                level: NONAPILevel::NOC,
                target: None,
                flags: 0,
            },
            object_id,
            access: Some(access),
        }).await?;
        Ok(())
    }

    async fn gen_aes_key_and_encrypt(&self) -> BuckyResult<(AesKey, Vec<u8>)> {
        let req = CryptoEncryptDataOutputRequest::new().by_device().gen_aeskey_and_encrypt();
        let resp = self.crypto().encrypt_data(req).await?;
        Ok((resp.aes_key.unwrap(), resp.result))
    }

    async fn decrypt_aes_key(&self, encrypt_aes_key: Vec<u8>) -> BuckyResult<AesKey> {
        let req = CryptoDecryptDataOutputRequest::new(encrypt_aes_key).by_device().decrypt_aeskey();
        let resp = self.crypto().decrypt_data(req).await?;
        Ok(AesKey::from(resp.data))
    }
}

pub struct SharedCyfsStackHolder {
    stack: SharedCyfsStack,
    is_stopped: bool,
}

impl SharedCyfsStackHolder {
    pub fn new(stack: SharedCyfsStack) -> Self {
        Self {
            stack,
            is_stopped: false,
        }
    }

    pub async fn stop(&mut self) {
        self.stack.stop().await;
        self.is_stopped = true;
    }
}

impl Clone for SharedCyfsStackHolder {
    fn clone(&self) -> Self {
        unreachable!("SharedCyfsStackHolder can't clone")
    }
}

impl Drop for SharedCyfsStackHolder {
    fn drop(&mut self) {
        async_std::task::block_on(self.stack.stop());
    }
}

impl Deref for SharedCyfsStackHolder {
    type Target = SharedCyfsStack;

    fn deref(&self) -> &Self::Target {
        &self.stack
    }
}
