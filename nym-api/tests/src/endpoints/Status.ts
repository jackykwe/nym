import { AxiosResponse } from "axios";
import {
  ActiveStatus,
  AvgUptime,
  ComputeRewardEstimation,
  CoreCount,
  DetailedGateway,
  InclusionProbability,
  NodeHistory,
  Report,
  RewardEstimation,
  StakeSaturation,
} from "../types/StatusInterfaces";
import { APIClient } from "./abstracts/APIClient";

export default class Status extends APIClient {
  constructor() {
    super("/status");
  }

  // GATEWAYS

  public async getDetailedGateways(): Promise<DetailedGateway> {
    const response = await this.restClient.sendGet({
      route: `/gateways/detailed`,
    });

    return response.data;
  }

  public async getGatewayStatusReport(identity_key: string): Promise<Report> {
    const response = await this.restClient.sendGet({
      route: `/gateway/${identity_key}/report`,
    });

    return response.data;
  }

  public async getGatewayHistory(identity_key: string): Promise<NodeHistory> {
    const response = await this.restClient.sendGet({
      route: `/gateway/${identity_key}/history`,
    });

    return response.data;
  }

  public async getGatewayCoreCount(identity_key: string): Promise<CoreCount> {
    const response = await this.restClient.sendGet({
      route: `/gateway/${identity_key}/core-status-count`,
    });

    return response.data;
  }


  // MIXNODES

  public async getMixnodeStatusReport(mix_id: number): Promise<Report> {
    const response = await this.restClient.sendGet({
      route: `/mixnode/${mix_id}/report`,
    });

    return response.data;
  }

  public async getMixnodeStakeSaturation(
    mix_id: number
  ): Promise<StakeSaturation> {
    const response = await this.restClient.sendGet({
      route: `/mixnode/${mix_id}/stake-saturation`,
    });

    return response.data;
  }

  public async getMixnodeCoreCount(mix_id: number): Promise<CoreCount> {
    const response = await this.restClient.sendGet({
      route: `/mixnode/${mix_id}/core-status-count`,
    });

    return response.data;
  }

  public async getMixnodeRewardComputation(
    mix_id: number
  ): Promise<RewardEstimation> {
    const response = await this.restClient.sendGet({
      route: `/mixnode/${mix_id}/reward-estimation`,
    });

    return response.data;
  }

  public async sendMixnodeRewardEstimatedComputation(
    mix_id: number
  ): Promise<ComputeRewardEstimation> {
    const response = await this.restClient.sendPost({
      route: `/mixnode/${mix_id}/compute-reward-estimation`,
    });

    return response.data;
  }

  public async getMixnodeHistory(mix_id: number): Promise<NodeHistory> {
    const response = await this.restClient.sendGet({
      route: `/mixnode/${mix_id}/history`,
    });

    return response.data;
  }

  public async getMixnodeAverageUptime(
    mix_id: number
  ): Promise<AvgUptime> {
    const response = await this.restClient.sendGet({
      route: `/mixnode/${mix_id}/avg_uptime`,
    });

    return response.data;
  }

  public async getMixnodeInclusionProbability(
    mix_id: number
  ): Promise<InclusionProbability> {
    const response = await this.restClient.sendGet({
      route: `/mixnode/${mix_id}/inclusion-probability`,
    });

    return response.data;
  }

  public async getMixnodeStatus(mix_id: number): Promise<ActiveStatus> {
    const response = await this.restClient.sendGet({
      route: `/mixnode/${mix_id}/status`,
    });

    return response.data;
  }
}
