def mvnCmd(String cmd) {
  sh 'mvn -B -s settings-jenkins.xml ' + cmd
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
                withCredentials([file(credentialsId: 'jenkins-maven-settings.xml', variable: 'SETTINGS_PATH')]) {
                  sh "cp ${SETTINGS_PATH} settings-jenkins.xml"
                }
            }
        }
        stage('Build with tests') {
            steps {
              mvnCmd("clean verify")
              publishCoverage adapters: [jacocoAdapter(path: '**/target/site/jacoco/jacoco.xml')], calculateDiffForChangeRequests: true, failNoReports: true
              junit allowEmptyResults: true, testResults: '**/target/surefire-reports/*.xml'
            }
        }

        stage('Publish SNAPSHOT to maven') {
            when {
                branch 'devel'
            }
            steps {
                mvnCmd("deploy -Pdev")
            }
        }

        stage('Publish to maven') {
            when {
                buildingTag()
            }
            steps {
                mvnCmd("deploy -Pprod")
            }
        }
    }
}
