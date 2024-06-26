PRODUCTION="production"
DEVELOPMENT="development"
STAGING="staging"
QA="qa"

def getNow() {
    new Date().format('yyyyMMdd')
}

def getProjectName(jobName) {
    return jobName.split('/')[0]
}

def isPrevStageSuccess(build) {
    return build.result == 'SUCCESS' || build.result == null
}

def isDeployable(env, build) {
    return isPrevStageSuccess(build) && (env == PRODUCTION || env == DEVELOPMENT || env == STAGING || env == QA)
}

def isDeployableToProduction(env, build) {
    return env == PRODUCTION && isDeployable(env, build)
}

pipeline {
    agent any

    environment {
       PROJECT_NAME="${getProjectName(env.JOB_NAME)}"
       BUILD="${env.BUILD_NUMBER}"
       VERSION="${getNow()}.${env.BUILD_NUMBER}"
       SONAR_URL="${env.SONAR_URL}"
       DOCKER_REGISTRY="${env.DOCKER_REGISTRY}"
       DOCKER_IMAGE="certigen"
       DOCKERFILE="Dockerfile"
       SONAR_TOKEN=credentials('sonar-token')
    }

    options {
        timeout(time: 10, unit: 'MINUTES')
        buildDiscarder(logRotator(numToKeepStr: '3'))
    }

    stages {
        stage('Prepare: Set env according to branch') {
            steps {
                script {
                    env.ENVIRONMENT = "local"
                    if (env.GIT_BRANCH ==~ /.*qa/) {
                        env.ENVIRONMENT = QA
                    } else if (env.GIT_BRANCH ==~ /.*staging/) {
                        env.ENVIRONMENT = STAGING
                    } else if (env.GIT_BRANCH ==~ /.*develop/) {
                        env.ENVIRONMENT = DEVELOPMENT
                    } else if (env.GIT_BRANCH ==~ /.*main/) {
                        env.ENVIRONMENT = PRODUCTION
                    }
                }
            }
        }

        stage('Setup: Install dependencies') {
            steps {
                sh '''
                  make setup
                '''
            }
        }

        stage('Swagger: Generate API docs') {
            steps {
                sh 'make docs'
            }
        }

        stage('Tests: Run tests, lint and coverage') {
            when {
                expression {
                    isPrevStageSuccess(currentBuild)
                }
            }
            steps {
                sh '''
                  make lint
                  make test
                '''
            }
            post {
                success {
                    cobertura(
                            coberturaReportFile: "coverage.xml",
                            onlyStable: false,
                            failNoReports: true,
                            failUnhealthy: false,
                            failUnstable: false,
                            autoUpdateHealth: true,
                            autoUpdateStability: true,
                            zoomCoverageChart: true,
                            maxNumberOfBuilds: 0,
                            lineCoverageTargets: '30, 30, 30',
                            conditionalCoverageTargets: '30, 30, 30',
                            classCoverageTargets: '30, 30, 30',
                            fileCoverageTargets: '30, 30, 30',
                    )
                }
            }
        }

        stage('Code analysis: SonarQube') {
            when {
                expression {
                    isPrevStageSuccess(currentBuild)
                }
            }
            steps {
                sh '''
                  sonar-scanner \
                  -Dsonar.projectKey=$PROJECT_NAME \
                  -Dsonar.projectName=$PROJECT_NAME \
                  -Dsonar.projectVersion=$VERSION \
                  -Dsonar.host.url=$SONAR_URL \
                  -Dsonar.token=$SONAR_TOKEN \
                  -Dsonar.sourceEncoding=UTF-8 \
                  -Dsonar.issuesReport.html.enable=true \
                  -Dsonar.report.export.path=sonar-report.json \
                  -Dsonar.sources=src \
                  -Dsonar.tests=src/ \
                  -Dsonar.exclusions=**/*_test.go,**/vendor/** \
                  -Dsonar.test.inclusions=**/*_test.go \
                  -Dsonar.test.exclusions=**/vendor/**
                '''
            }
        }

        stage('Release: Create git tag') {
            when {
                expression {
                    isDeployableToProduction(env.ENVIRONMENT, currentBuild)
                }
            }
            steps {
                script {
                    withCredentials([sshUserPrivateKey(credentialsId: 'gitea-user-jenkins-sshkey', keyFileVariable: 'SSH_KEY')]) {
                        sh '''
                            git remote set-url origin ssh://git@${INTERNAL_GIT_URL}/product/${PROJECT_NAME}.git 2>/dev/null || echo
                            git tag -a v${VERSION} -m "Created by Jenkins"
                            GIT_SSH_COMMAND="ssh -i ${SSH_KEY}" git push origin v${VERSION}
                        '''
                    }
                }
            }
        }

        stage('Deploy: docker build') {
            when {
                expression {
                    isDeployableToProduction(env.ENVIRONMENT, currentBuild)
                }
            }
            steps {
                script {
                    withCredentials([file(credentialsId: "config.${ENVIRONMENT}.yaml", variable: 'CONFIG_YAML')]) {
                        sh '''
                          cp ${CONFIG_YAML} bin/config.yaml
                          docker build -f ${DOCKERFILE} -t=${DOCKER_REGISTRY}/${PROJECT_NAME}/${DOCKER_IMAGE}:${VERSION} .
                          docker tag ${DOCKER_REGISTRY}/${PROJECT_NAME}/${DOCKER_IMAGE}:${VERSION} ${DOCKER_REGISTRY}/${PROJECT_NAME}/${DOCKER_IMAGE}:latest
                          docker push ${DOCKER_REGISTRY}/${PROJECT_NAME}/${DOCKER_IMAGE}:latest
                        '''
                    }
                }
            }
        }
    }
}

