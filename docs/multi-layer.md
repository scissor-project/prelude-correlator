#Multi-Layer Correlation

Suppose that you want to establish a correlation composed by multiple layers of abstraction, for example <i>n</i> levels of abstraction with <i>m</i> components in the first layer (base level), <i>i</i> in the second layer (more abstract level) , ... , <i>j</i> in the <i>n</i>-th layer (most abstract level).  
Prelude Correlator is based on plugins. With each plugin, you can write your own correlation rule and send correlation alerts (IDMEF messages).  When you generate a correlation alert, it is sent to Prelude Manager and also to the other plugins running in your Prelude Correlator instance.  This is a simple approach to make multi-layer correlation. Just consider a plugin as a member of a layer of correlation, in this case you can build <i>m</i> plugins to process the first layer, <i>i</i> plugins to process the second layer , ... , <i>j</i> plugins to process the <i>n</i>-th layer.  

That's it, to generate a correlation alert and send it to Prelude Manager and the other plugins in your Prelude Correlator instance, just call the alert method provided by IDMEF or, if you want to use ContextHelper, call the method <i>generateCorrelationAlert</i>.  
To begin, two examples of entry and advanced plugins are provided (EntryLevelCorrelator, AdvancedLevelCorrelator).
