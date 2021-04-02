use usiem::components::SiemComponent;
use std::sync::Arc;
use crossbeam_channel::{Receiver, Sender};
use super::urule::SiemSigmaRule;
use super::rule::SigmaRule;
use usiem::components::common::{
    CommandDefinition, SiemComponentCapabilities, SiemComponentStateStorage, SiemFunctionCall,
    SiemFunctionType, SiemMessage, UserRole,
};
use std::borrow::Cow;
use usiem::events::field::SiemField;
use usiem::events::SiemLog;

struct SigmaEngine {
    rules : Vec<Arc<SigmaRule>>,
    local_chnl_snd : Sender<SiemMessage>,
    log_receiver : Receiver<SiemLog>,
    kernel_sender : Sender<SiemMessage>,
    conn : Option<Box<dyn SiemComponentStateStorage>>
}

impl SiemComponent for SigmaEngine {
    fn name(&self) -> Cow<'static, str> {
        Cow::Borrowed("ElasticSearchOutput")
    }
    fn local_channel(&self) -> Sender<SiemMessage> {
        self.local_chnl_snd.clone()
    }
    fn set_log_channel(&mut self, _sender: Sender<SiemLog>, receiver: Receiver<SiemLog>) {
        self.log_receiver = receiver;
    }
    fn set_kernel_sender(&mut self, sender: Sender<SiemMessage>) {
        self.kernel_sender = sender;
    }
    /// Allow to store information about this component like the state or conigurations.
    fn set_storage(&mut self, conn: Box<dyn SiemComponentStateStorage>) {
        self.conn = Some(conn);
    }

    /// Capabilities and actions that can be performed on this component
    fn capabilities(&self) -> SiemComponentCapabilities {
        let datasets = Vec::new();
        let mut commands = Vec::new();

        let stop_component = CommandDefinition::new(SiemFunctionType::STOP_COMPONENT,Cow::Borrowed("Stop SigmaEngine") ,Cow::Borrowed("This allows stopping all SigmaEngine components.\nUse only when really needed.") , UserRole::Administrator);
        commands.push(stop_component);
        let start_component = CommandDefinition::new(
            SiemFunctionType::START_COMPONENT,// Must be added by default by the KERNEL and only used by him
            Cow::Borrowed("Start SigmaEngine"),
            Cow::Borrowed("This starts processing logs."),
            UserRole::Administrator,
        );
        commands.push(start_component);
        SiemComponentCapabilities::new(
            Cow::Borrowed("SigmaEngine"),
            Cow::Borrowed("Trigert alerts using Sigma Rules"),
            Cow::Borrowed(""),
            datasets,
            commands,
        )
    }

    /// Execute the logic of this component in an infinite loop. Must be stopped using Commands sent using the channel.
    fn run(&mut self) {

    }
}