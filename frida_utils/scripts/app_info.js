Java.perform(function() {
    var ActivityThread = Java.use('android.app.ActivityThread');
    var Context = Java.use('android.content.Context');
    
    var currentApplication = ActivityThread.currentApplication();
    var context = currentApplication.getApplicationContext();
    
    console.log('\\n[App Information]');
    console.log('Package Name:', context.getPackageName());
    console.log('Process Name:', ActivityThread.currentProcessName());
    console.log('App Version:', context.getPackageManager().getPackageInfo(context.getPackageName(), 0).versionName.value);
    console.log('Target SDK:', context.getApplicationInfo().targetSdkVersion.value);
    
    // List all activities
    var packageInfo = context.getPackageManager().getPackageInfo(context.getPackageName(), 
                     Java.use('android.content.pm.PackageManager').GET_ACTIVITIES.value);
    console.log('\\n[Activities]');
    packageInfo.activities.value.forEach(function(activity) {
        console.log(activity.name.value);
    });
});