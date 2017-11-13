# Abstract Correlation Logic
Prelude Correlator provides the class Context to keep track of a given plugin state.  
If you want to create a correlation logic over the class Context that can be extended and reused by several plugins just start extending the class ContextHelper.  ContextHelper is a wrapper of the Context class provided by Prelude Correlator, it just contains a context and a few abstract methods to build your own logic over the given context.  StrongWindowHelper and WeakWindowHelper are an example of two classes that extend the ContextHelper class to provide a correlation logic based on a specific correlation period (window) like counting the number of idmef received in a window of 5 seconds.
The method <i>getContextHelper</i> is provided to retrieve a ContextHelper with a specific id, or create a new one if doesn't exists. In this case the ContextHelper is an instance of StrongWindowHelper.  

```
ctxHelper = self.getContextHelper(context_id,StrongWindowHelper)
```

Note that the mapping between ContextHelper and Context is 1:1, the id of the ContextHelper instance should be the id that you want to assign to a Context instance.  
To check if a ContextHelper instance has already an existing Context  instance inside, we use the <i>isEmpty()</i> method.  
In this example, if <i>ctxHelper.isEmpty()</i> is True, we call the bindContext method to create a Context instance with options defined by the <i>"options"</i> variable and with initial fields defined by the <i>initial\_fields</i> variable (a context has an embedded idmef message that might be used to generate a correlation alert).

```
if ctxHelper.isEmpty():
         options = { "expire": 5, "threshold": 5 ,"alert_on_expire": False, "window": 5}
         initial_fields = {"alert.correlation_alert.name": "MyFirstCorrelationAlert","alert.classification.text": "MyFirstClassification",alert.assessment.impact.severity": "high"}

         #Create a context that:
         #expires after 5 seconds of inactivity
         #generates a correlation alert if at least 5 idmef received
         #checks for the threshold in a window of 5 seconds
         ctxHelper.bindContext(options, initial_attrs)
```

Several correlation logics have several behaviors during the reception of an idmef message, this is why we define the method processIdmef with an idmef as parameter and the possibility to add the alert reference of this idmef to the context. In this case we want to add a reference of the idmef to the context.

```
ctxHelper.processIdmef(idmef=idmef, addAlertReference=True)
```

In the end, we generate a correlation alert if a successful correlation is obtained. The correlation check is provided by the method <i>checkCorrelation</i>. The correlation alert is generated with the method <i>generateCorrelationAlert</i>. When generating a correlation alert it is possible to specify if the alert has to be sent to the manager and to the other plugins or just returned. It is also possible to destroy the context inside <i>ctxHelper</i>, this could be useful when you want to restart from scratch after a successful correlation.


```
if ctxHelper.checkCorrelation():
	ctxHelper.generateCorrelationAlert(send=True, destroy_ctx=False)
```



## WeakWindowHelper
In WeakWindowHelper we define an option <i>"window"</i> in the context and consider a window as the period between the reception of the first idmef and the expiration of the time value set in the option <i>"window"</i> (e.g. 5 seconds). When the window expires the correlation period restarts.
Suppose you simply want to generate a correlation alert if more than 5 idmef are received in a fixed window of 5 seconds.

First, you have to create a WeakWindowHelper.  

```
ctxHelper = self.getContextHelper(context_id, WeakWindowHelper)
```

Since the idmefs received are all the same, we add an alert reference only at the beginning (when there is no Context instance inside <i>ctxHelper</i>).  
When the window expires the timer of the correlation period restarts. In this case we define a specific option of WeakWindowHelper named <i>"reset\_ctx\_on\_window\_expiration"</i>, if set to True, when the window expires, we want also to reset the Context instance inside <i>ctxHelper</i>. This could be useful when we want to start from scratch (e.g. reset the context to have no alert references) when a window expires. In this case we just want to reset the ctxHelper timer when a window expires so we set <i>"reset\_ctx\_on\_window\_expiration"</i> to False.    

```
if ctxHelper.isEmpty():
         options = { "expire": 5, "threshold": 5 ,"alert_on_expire": False, "window": 5, "reset_ctx_on_window_expiration": False}
         initial_fields = {"alert.correlation_alert.name": "MyFirstCorrelationAlert","alert.classification.text": "MyFirstClassification",alert.assessment.impact.severity": "high"}

         #Create a context that:
         #expires after 5 seconds of inactivity
         #generates a correlation alert after 5 msg received
         #checks for the threshold in a window of 5 seconds
         correlator.bindContext(options, initial_attrs)
         correlator.processIdmef(idmef=idmef, addAlertReference=True)
else:
         correlator.processIdmef(idmef=idmef, addAlertReference=False)
```

Now we check for a successful correlation. When calling the  <i>checkCorrelation</i> method, the default behavior is to check if the internal context threshold is reached. In this case, generate a correlation alert if received at least 5 idmef. If the threshold is reached, a new correlation alert is generated and the ctxHelper timer is reset, so a new correlation period (window) restarts.

```
if ctxHelper.checkCorrelation():
	correlator.generateCorrelationAlert(send=True, destroy_ctx=False)
```


## StrongWindowHelper
Another correlation logic could be to "shift" the correlation period (window) every time an idmef is received.  
In StrongWindowHelper we define an option <i>"window"</i> in the context and use a list to store the timestamps in which idmefs are received. Every time that the <i>processIdmef()</i> method is called, the list is scanned to check if some timestamps are expired. Retrieved the idmefs received in the correlation period defined by the option <i>"window"</i>, if the correlation is successful, a correlation alert is raised.  
Suppose that we want to generate a correlation alert if at least 5 idmef are received in a window of 5 seconds. Consider a ContextHelper as a list to store idmef.   
At the beginning we have an empty list.  
We receive the first idmef at time <i>x</i>, the list's length is 1 and the correlation period starts.

time x   

StrongWindowHelper idmef_list = [idmef1]   

WeakWindowHelper idmef_list = [idmef1]                   


Just for simplicity reasons, suppose that we can receive multiple idmef at the same time.
After 3 seconds, we receive 3 idmef, the list's length is 4.

time x+3  

StrongWindowHelper idmef_list = [idmef1, idmef2, idmef3]

WeakWindowHelper idmef_list = [idmef1, idmef2, idmef3]

After 3 seconds, let's say time <i>t</i>=<i>x</i>+6, we receive 2 idmef.  

time t = x+6  

StrongWindowHelper idmef_list = [idmef2, idmef3, idmef4, idmef5, idmef6]  

WeakWindowHelper idmef_list = [idmef5, idmef6]

The difference between WeakWindowHelper and StrongWindowHelper is that WeakWindowHelper's list length is 2 and StrongWindowHelper's length is 5, so StrongWindowHelper will return True if we call the  checkCorrelation method. This happens because WeakWindowHelper checks if the window is expired and simply restarts a new correlation period that, in this case, started 6 seconds before the reception of the last 2 idmefs. StrongWindowHelper scans the list and checks if from time t to time <i>t</i> - 5 (window is 5 seconds) there is a sufficient amount of idmef to generate a correlation alert. From the point of view of WeakWindowHelper, the window is expired when the last 2 idmef are received because <i>t</i>-<i>x</i> > 5, so the window contains 2 idmef and the correlation period restarts at time <i>t</i>. StrongWindowHelper's window, instead, is shifted.
