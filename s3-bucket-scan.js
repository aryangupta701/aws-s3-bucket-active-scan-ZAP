const URL = Java.type('java.net.URL')

function getPermissionsUsingAwsSdk(leakedUrl) {
  var hasReadPermission = false;
  var hasWritePermission = false;
  var parsedUrl = new URL(leakedUrl);
  var bucketName = parsedUrl.getHost().split('.')[0];
  var objectKey = parsedUrl.getPath().substring(1);
  var region = parsedUrl.getHost().split('.')[2];

  var AWS = Java.type('software.amazon.awssdk.services.s3.S3Client');
  var client = AWS.builder()
    .region(region)
    .build();
 
  try {
    var aclParams = Java.type('software.amazon.awssdk.services.s3.model.GetObjectAclRequest').builder()
      .bucket(bucketName)
      .key(objectKey)
      .build();

    var aclResult = client.getObjectAcl(aclParams);
    var grants = aclResult.grants();

    for (var i = 0; i < grants.size(); i++) {
      var grant = grants.get(i);
      if ( grant.permission().toString() === 'READ' ) {
        hasReadPermission = true;
      }
      if (grant.permission().toString() === 'WRITE') {
        hasWritePermission = true;
      }
    }

    print('Read Permission: ' + hasReadPermission);
    print('Write Permission: ' + hasWritePermission);
  } catch (error) {
    print('Error: ' + error);
  }
  return {hasReadPermission, hasWritePermission};
}

function getPermissionUsingHttp(url) {
  var hasReadPermission = false;
  var hasWritePermission = false;
  fetch(url)
  .then(response => {
    if (response.ok) {
      hasReadPermission = true;
    }
  })
  .catch(err => {
    print(err); 
  });

  fetch(url, {
    method: 'PUT',
    body: "fileContent"
  })
    .then(response => {
      if (response.ok) {
        hasWritePermission = true;
      }
    })
    .catch(err => {
      print(err); 
    });
  return {hasReadPermission, hasWritePermission};
}

function checkForS3BucketURLLeakage(as, msg, param) {
  var requestUri = msg.getRequestHeader().getURI().toString();
  var regexs = [/s3\.[^.]+\.amazonaws\.com/, /s3\.amazonaws\.com/];
  var isLeakingS3BucketURL = false;

  for (var i = 0; i < regexs.length; i++) {
    var regex = regexs[i];

    if (requestUri.match(regex)) {
      isLeakingS3BucketURL = true;
      break;
    }
  }

  if (isLeakingS3BucketURL) {
      
      var permissions = getPermissionsUsingAwsSdk(); 
      // var permissions = getPemissionsUsingHttp();  
      var isBucketReadable = permissions.hasReadPermission;
      var isBucketWritable = permissions.hasWritePermission;

      var risk = 1
      var confidence = 3
      if(isBucketReadable) risk = 2; 
      if(isBucketWritable) risk = 3; 
      var alert = as.newAlert()
          .setRisk(risk)
          .setConfidence(confidence)
          .setName('S3 Bucket Leakage')
          .setDescription(
                `The HTTP message is leaking an S3 bucket URL. 
                ${isBucketReadable ? "Then bucket is Readable." :""}
                ${isBucketWritable ? "The Bucket is Writable" :""}` 
          )
          .setParam(param)
          .setAttack('N/A')
          .setEvidence('Evidence')
          .setOtherInfo('')
          .setSolution('https://docs.aws.amazon.com/AmazonS3/latest/userguide/DataDurability.html')
          .setReference('https://docs.aws.amazon.com/AmazonS3/latest/userguide/DataDurability.html')
          .setCweId(0)
          .setWascId(0)
          .setMessage(msg);
      alert.raise();
  }
}

function scanNode(as, msg) {
  print('scan node called for url=' + msg.getRequestHeader().getURI().toString()); 
  checkForS3BucketURLLeakage(as, msg, ''); 
}

function scan(as, msg, param, value) {
  print('scan called for url=' + msg.getRequestHeader().getURI().toString() +
     ' param=' + param + ' value=' + value);
  checkForS3BucketURLLeakage(as, msg, param); 
}