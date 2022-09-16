def mvnCmd(String cmd) {
  sh 'mvn -B -s settings.xml ' + cmd
}

pipeline {
    agent {
        node {
            label 'carbonio-agent-v1'
        }
    }
    environment {
        JAVA_OPTS = '-Dfile.encoding=UTF8'
        LC_ALL = 'C.UTF-8'
        ARTIFACTORY_ACCESS=credentials('artifactory-jenkins-gradle-properties-splitted')
        BUILD_PROPERTIES_PARAMS='-Dartifactory_user=$ARTIFACTORY_ACCESS_USR -Dartifactory_password=$ARTIFACTORY_ACCESS_PSW'
        jenkins_build = 'true'
    }
    options {
        buildDiscarder(logRotator(numToKeepStr: '25'))
        timeout(time: 2, unit: 'HOURS')
        skipDefaultCheckout()
    }
    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }
        stage('Build with tests') {
            steps {
              mvnCmd("$BUILD_PROPERTIES_PARAMS clean verify")
            }
        }

        stage('Publish to maven') {
            when {
                buildingTag()
            }
            steps {
                mvnCmd("$BUILD_PROPERTIES_PARAMS deploy")
            }
        }
    }
}

